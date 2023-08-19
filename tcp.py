import asyncio
from tcputils import *
import random

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)  # Alterando para _rdt_rcv

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segmento):  # Alterando _rdt_receber para _rdt_rcv
        src_porta, dst_porta, num_seq, num_ack, \
            flags, tamanho_janela, checksum, urg_ptr = read_header(segmento)

        payload = segmento[4 * (flags >> 12):]  # Alterando carga_util para payload
        id_conexao = (src_addr, src_porta, dst_addr, dst_porta)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            conexao.num_seq = random.randint(0, 0xffff)
            conexao.num_ack = num_seq + 1

            segmento_syn_ack = make_header(
                dst_porta,
                src_porta,
                conexao.num_seq,
                conexao.num_ack,
                FLAGS_SYN | FLAGS_ACK
            )

            self.rede.enviar(fix_checksum(segmento_syn_ack, dst_addr, src_addr), src_addr)
            conexao.num_seq += 1

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(num_seq, num_ack, flags, payload)  # Alterando chamada para _rdt_rcv
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_porta, dst_addr, dst_porta))

class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)
        self.num_seq = 0
        self.num_ack = 0

    def _exemplo_timer(self):
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, num_seq, num_ack, flags, payload):  # Alterando _rdt_receber para _rdt_rcv e carga_util para payload
        dst_addr, dst_porta, src_addr, src_porta = self.id_conexao

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.callback(self, payload)
            self.num_ack += 1
            sndpkt = fix_checksum(make_header(src_porta, dst_porta, self.num_seq, self.num_ack, FLAGS_ACK), src_addr, dst_addr)
            self.servidor.rede.enviar(sndpkt, dst_addr)
        elif len(payload) <= 0:
            return
        else:
            if self.num_ack != num_seq:
                return 
            self.callback(self, payload)
            self.num_ack += len(payload)
            sndpkt = fix_checksum(make_header(src_porta, dst_porta, self.num_seq, self.num_ack, FLAGS_ACK), src_addr, dst_addr)
            self.servidor.rede.enviar(sndpkt, dst_addr)
            print('recebido payload: %r' % payload)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        dst_addr, dst_porta, src_addr, src_porta = self.id_conexao
        vezes_maior = int(len(dados) / MSS)
        contador = 0
        if len(dados) > MSS:
            while contador < vezes_maior:
                pos_inicial = contador * MSS
                pos_final = (contador + 1) * MSS
                dados_quebrados = dados[pos_inicial:pos_final]
                segmento = fix_checksum(make_header(src_porta, dst_porta, self.num_seq, self.num_ack, 0 | FLAGS_ACK) + dados_quebrados, src_addr, dst_addr)
                self.servidor.rede.enviar(segmento, dst_addr)
                self.num_seq += len(dados_quebrados)
                contador += 1
        else:
            segmento = fix_checksum(make_header(src_porta, dst_porta, self.num_seq, self.num_ack, 0 | FLAGS_ACK) + dados, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, dst_addr)
            self.num_seq += len(dados)

    def fechar(self):
        dst_addr, dst_porta, src_addr, src_porta = self.id_conexao
        header = make_header(src_porta, dst_porta, self.num_seq, self.num_ack, FLAGS_FIN)
        segmento = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, dst_addr)
        self.num_ack += 1

        self._enviar_ack(dst_porta, src_porta)

    def _enviar_ack(self, src_porta, dst_porta):
        header = make_header(dst_porta, src_porta, self.num_seq, self.num_ack, FLAGS_ACK)
        segmento = fix_checksum(header, self.id_conexao[2], self.id_conexao[0])
        self.servidor.rede.enviar(segmento, self.id_conexao[2])



