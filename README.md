# Protocolo de transporte confiável sobre UDP

*Reliable transport protocol over UDP in C (raw sockets): handshake, sliding window, checksum, cumulative ACKs, retransmission and simulated packet loss.*

Trabalho prático de Redes de Computadores (UFMT, Engenharia de Computação, 2025/2). Um emissor (`client.c`) e um receptor (`server.c`) em C transferem um arquivo sobre UDP. Toda a confiabilidade que o TCP daria é feita à mão, no espaço de usuário: os cabeçalhos IP e UDP são montados e lidos com socket RAW.

## O que o protocolo faz

| Mecanismo | Como foi feito |
|---|---|
| Cabeçalho próprio | 16 bytes, descrito em [`reliable_udp.h`](reliable_udp.h): número de sequência, ACK, janela anunciada, tamanho do payload, checksum, flags (`SYN`, `ACK`, `DAT`, `FIN`) e um byte de alinhamento |
| Conexão | handshake em três vias (`SYN`, `SYN|ACK`, `ACK`), com retransmissão se der timeout; encerramento com `FIN` |
| Sequência e duplicatas | números de sequência por byte, com comparação que tolera o estouro dos 32 bits; o receptor descarta duplicatas e segmentos fora de ordem e reenvia o ACK |
| Janela deslizante | o emissor mantém vários segmentos em trânsito, limitados por uma janela em bytes (`-w`) |
| Verificação de erro | checksum de 16 bits (soma em complemento de 1, como o da Internet) sobre cabeçalho e dados; segmento com erro é descartado |
| Retransmissão | cada segmento na janela tem seu próprio temporizador (`-t`); o ACK é cumulativo |
| Perdas simuladas | o receptor pode descartar segmentos de propósito: modelo `bernoulli` (perda independente) ou `bimodal` (rajadas de perda) |

No fim, os dois lados imprimem métricas (tempo, enviados, retransmissões, ACKs, descartados) e o SHA-256 do arquivo, para conferir que ele chegou inteiro.

## Como rodar

Precisa de Linux e de `sudo`, porque socket RAW exige privilégio de root.

```bash
gcc server.c -o server
gcc client.c -o client

# terminal 1: receptor (porta 8080, grava em recebido.txt)
sudo ./server -o recebido.txt

# terminal 2: emissor
sudo ./client -f exemplos/pi-100k.txt -a 127.0.0.1
```

Opções do emissor: `-a` IP (padrão `127.0.0.1`), `-p` porta (`8080`), `-w` janela em bytes (`10000`), `-s` tamanho do segmento (`1000`), `-t` timeout em ms (`500`) e `-v` para mostrar cada segmento.

Opções do receptor: `-p` porta, `-w` janela anunciada, `-o` arquivo de saída, `--seed` semente do sorteio de perdas e `-v`. Para simular perdas, use `--loss-model bernoulli --p-loss 0.1` ou `--loss-model bimodal --bimodal-params alfa,p_baixa,p_alta,tamanho_da_rajada`.

O arquivo de exemplo, `exemplos/pi-100k.txt`, tem os 100 mil primeiros dígitos de π (cerca de 200 KB).

### Teste feito

Os dois programas foram compilados (estáticos, para Linux x86-64) e rodaram pela interface de loopback, com o arquivo de exemplo:

| Cenário | Tempo | Descartados pelo receptor | Arquivo recebido |
|---|---:|---:|---|
| sem perda | 0,002 s | 0 | SHA-256 igual ao original |
| perda de 10 % (`bernoulli`) | 21,2 s | 57 | SHA-256 igual ao original |

## Estrutura

| Arquivo | O que é |
|---|---|
| `reliable_udp.h` | formato do cabeçalho, flags e o cálculo do checksum |
| `client.c` | emissor: handshake, janela deslizante, temporizadores e retransmissão |
| `server.c` | receptor: verificação do checksum, ordem e duplicatas, ACK cumulativo e simulação de perdas |
| `exemplos/` | arquivo usado nos testes |

## O que aprendi

Todas as partes tiveram sua dificuldade: o handshake, a janela e a retransmissão. Numa próxima vez, eu dividiria o trabalho em atividades pequenas, feitas uma de cada vez, porque juntar tudo de uma vez numa atividade complexa faz você se perder tentando deixar tudo funcionando perfeitamente.
