import asyncio
from tcputils import *
import random


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            conexao.seq_no = random.randint(0, 0xffff)
            conexao.ack_no = seq_no + 1

            syn_ack_segment = make_header(
                dst_port,
                src_port,
                conexao.seq_no,
                conexao.ack_no,
                FLAGS_SYN | FLAGS_ACK
            )

            self.rede.enviar(fix_checksum(syn_ack_segment, dst_addr, src_addr), src_addr)
            conexao.seq_no += 1

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)
        self.seq_no = 0
        self.ack_no = 0

    def _exemplo_timer(self):
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.callback(self, payload)
            self.ack_no += 1
            sndpkt = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
            self.servidor.rede.enviar(sndpkt, dst_addr)
        elif len(payload) <= 0:
            return
        else:
            if self.ack_no != seq_no:
                return 
            self.callback(self, payload)
            self.ack_no += len(payload)
            sndpkt = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
            self.servidor.rede.enviar(sndpkt, dst_addr)
            print('recebido payload: %r' % payload)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        vezes_maior = int(len(dados) / MSS)
        counter = 0
        if len(dados) > MSS:
            while counter < vezes_maior:
                pos_inicial = counter * MSS
                pos_final = (counter + 1) * MSS
                dados_quebrados = dados[pos_inicial:pos_final]
                segmento = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, 0 | FLAGS_ACK) + dados_quebrados, src_addr, dst_addr)
                self.servidor.rede.enviar(segmento, dst_addr)
                self.seq_no += len(dados_quebrados)
                counter += 1
        else:
            segmento = fix_checksum(make_header(src_port, dst_port, self.seq_no, self.ack_no, 0 | FLAGS_ACK) + dados, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento, dst_addr)
            self.seq_no += len(dados)

    def fechar(self):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        segmento = make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento_correto = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento_correto, dst_addr)
        self.ack_no += 1
