#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include "reliable_udp.h"

#define MAX_BUFFER 2048

// Macros para lidar com wrap-around de números de sequência (estouro do limite de 32 bits)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GE(a, b) ((int32_t)((a) - (b)) >= 0)

typedef struct {
    int active;
    uint32_t seq_num;
    int payload_len;
    char packet[MAX_BUFFER];
    int packet_len;
    long long send_time;
} WindowSlot;

long metric_total_sent = 0;
long metric_retransmits = 0;
long metric_acks_recv = 0;

long long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
}

void print_hash(const char *filename) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sha256sum %s", filename);
    printf(">> Executando hash local:\n");
    system(cmd);
}

int main(int argc, char **argv) {
    char *filename = NULL;
    char *target_ip = "127.0.0.1";
    int target_port = 8080;
    int window_size_bytes = 10000; // Agora gerenciado puramente em Bytes
    int segment_size = 1000;
    int timeout_ms = 500;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) filename = argv[++i];
        else if (strcmp(argv[i], "-a") == 0) target_ip = argv[++i];
        else if (strcmp(argv[i], "-p") == 0) target_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-w") == 0) window_size_bytes = atoi(argv[++i]);
        else if (strcmp(argv[i], "-s") == 0) segment_size = atoi(argv[++i]);
        else if (strcmp(argv[i], "-t") == 0) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
    }

    if (!filename) {
        fprintf(stderr, "Uso: %s -f <arquivo> [-a ip] [-p porta] [-w janela_BYTES] [-s seg_size] [-t timeout_ms] [-v]\n", argv[0]);
        exit(1);
    }

    FILE *file = fopen(filename, "rb");
    if (!file) { perror("Erro ao abrir arquivo"); exit(1); }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("Erro socket RAW (Você usou sudo?)"); exit(1); }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &dest_addr.sin_addr);

    // O limite máximo de segmentos guardados no buffer
    int max_slots = (window_size_bytes / segment_size) + 2; 
    WindowSlot *window = calloc(max_slots, sizeof(WindowSlot));
    
    uint32_t client_isn = 0;
    uint32_t base_seq = client_isn + 1;
    uint32_t next_seq = client_isn + 1;
    int eof_reached = 0;
    int file_done = 0;

    long long start_time = get_time_ms();

    // Handshake (SYN -> SYN|ACK -> ACK)
    if (verbose) printf(">>> Iniciando handshake (SYN)\n");
    int handshake_done = 0;

    while (!handshake_done) {
        char syn_packet[128];
        struct udphdr *syn_udp = (struct udphdr *)syn_packet;
        rudp_header_t *syn_rudp = (rudp_header_t *)(syn_packet + sizeof(struct udphdr));

        syn_udp->source = htons(12345);
        syn_udp->dest = htons(target_port);
        syn_udp->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t));
        syn_udp->check = 0;

        syn_rudp->seq_num = htonl(client_isn);
        syn_rudp->ack_num = 0;
        syn_rudp->window = htons(window_size_bytes > 65535 ? 65535 : window_size_bytes);
        syn_rudp->length = 0;
        syn_rudp->flags = FLAG_SYN;
        syn_rudp->padding = 0;
        syn_rudp->checksum = 0;
        syn_rudp->checksum = calculate_checksum(syn_rudp, sizeof(rudp_header_t));

        sendto(sock, syn_packet, sizeof(struct udphdr) + sizeof(rudp_header_t), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        metric_total_sent++;

        fd_set hs_read_fds;
        FD_ZERO(&hs_read_fds);
        FD_SET(sock, &hs_read_fds);

        struct timeval hs_tv;
        hs_tv.tv_sec = timeout_ms / 1000;
        hs_tv.tv_usec = (timeout_ms % 1000) * 1000;

        int hs_ret = select(sock + 1, &hs_read_fds, NULL, NULL, &hs_tv);

        if (hs_ret > 0) {
            char recv_buf[MAX_BUFFER];
            int n = recvfrom(sock, recv_buf, MAX_BUFFER, 0, NULL, NULL);

            if (n > 0) {
                int ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                struct udphdr *recv_udph = (struct udphdr *)(recv_buf + ip_hdr_len);

                if (ntohs(recv_udph->dest) == 12345) {
                    rudp_header_t *recv_rudph = (rudp_header_t *)(recv_buf + ip_hdr_len + sizeof(struct udphdr));
                    uint32_t srv_seq = ntohl(recv_rudph->seq_num);
                    uint32_t ack = ntohl(recv_rudph->ack_num);

                    if ((recv_rudph->flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK) && ack == client_isn + 1) {
                        if (verbose) printf("[-] SYN|ACK recebido. Finalizando handshake com ACK\n");

                        char ack_packet[128];
                        struct udphdr *ack_udp = (struct udphdr *)ack_packet;
                        rudp_header_t *ack_rudp = (rudp_header_t *)(ack_packet + sizeof(struct udphdr));

                        ack_udp->source = htons(12345);
                        ack_udp->dest = htons(target_port);
                        ack_udp->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t));
                        ack_udp->check = 0;

                        ack_rudp->seq_num = htonl(client_isn + 1);
                        ack_rudp->ack_num = htonl(srv_seq + 1);
                        ack_rudp->window = htons(window_size_bytes > 65535 ? 65535 : window_size_bytes);
                        ack_rudp->length = 0;
                        ack_rudp->flags = FLAG_ACK;
                        ack_rudp->padding = 0;
                        ack_rudp->checksum = 0;
                        ack_rudp->checksum = calculate_checksum(ack_rudp, sizeof(rudp_header_t));

                        sendto(sock, ack_packet, sizeof(struct udphdr) + sizeof(rudp_header_t), 0,
                               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        metric_total_sent++;
                        handshake_done = 1;
                    }
                }
            }
        } else if (verbose) {
            printf("[!] Timeout no handshake. Retransmitindo SYN...\n");
        }
    }

    while (!file_done) {
        // 1. Controle de Fluxo: Janelamento baseado em Bytes
        uint32_t unacked_bytes = next_seq - base_seq;
        
        while (!eof_reached && unacked_bytes < (uint32_t)window_size_bytes) {
            // Calcula o quanto ainda pode ser enviado (tamanho do segmento ou o resto do espaço da janela)
            int bytes_allowed = window_size_bytes - unacked_bytes;
            int bytes_to_read = (bytes_allowed < segment_size) ? bytes_allowed : segment_size;

            // Busca um slot livre no buffer
            int free_slot = -1;
            for (int i = 0; i < max_slots; i++) {
                if (!window[i].active) { free_slot = i; break; }
            }
            if (free_slot == -1) break; // Falha de segurança, buffer cheio

            char payload[1500];
            int read_len = fread(payload, 1, bytes_to_read, file);
            
            if (read_len < bytes_to_read) eof_reached = 1;

            if (read_len > 0) {
                WindowSlot *slot = &window[free_slot];
                slot->active = 1;
                slot->seq_num = next_seq;
                slot->payload_len = read_len;
                
                struct udphdr *udph = (struct udphdr *)slot->packet;
                rudp_header_t *rudph = (rudp_header_t *)(slot->packet + sizeof(struct udphdr));
                char *data_ptr = slot->packet + sizeof(struct udphdr) + sizeof(rudp_header_t);

                udph->source = htons(12345);
                udph->dest = htons(target_port);
                udph->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t) + read_len);
                udph->check = 0;

                rudph->seq_num = htonl(next_seq);
                rudph->ack_num = 0;
                rudph->window = htons(window_size_bytes > 65535 ? 65535 : window_size_bytes);
                rudph->length = htons(read_len);
                rudph->flags = FLAG_DAT;
                rudph->padding = 0;
                
                memcpy(data_ptr, payload, read_len);

                rudph->checksum = 0;
                rudph->checksum = calculate_checksum(rudph, sizeof(rudp_header_t) + read_len);

                slot->packet_len = sizeof(struct udphdr) + sizeof(rudp_header_t) + read_len;
                sendto(sock, slot->packet, slot->packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                slot->send_time = get_time_ms();
                metric_total_sent++;

                if (verbose) printf("[+] Enviado seq=%u, len=%d (Janela uso: %u/%d)\n", next_seq, read_len, unacked_bytes + read_len, window_size_bytes);
                
                next_seq += read_len;
                unacked_bytes = next_seq - base_seq;
            } else {
                eof_reached = 1;
                break;
            }
        }

        if (eof_reached && base_seq == next_seq) {
            file_done = 1;
            break; // Todos os bytes confirmados
        }

        // 2. Aguarda ACKs
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms poll

        int ret = select(sock + 1, &read_fds, NULL, NULL, &tv);

        if (ret > 0) {
            char recv_buf[MAX_BUFFER];
            int n = recvfrom(sock, recv_buf, MAX_BUFFER, 0, NULL, NULL);

            if (n > 0) {
                int ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                struct udphdr *recv_udph = (struct udphdr *)(recv_buf + ip_hdr_len);
                
                if (ntohs(recv_udph->dest) == 12345) { 
                    rudp_header_t *recv_rudph = (rudp_header_t *)(recv_buf + ip_hdr_len + sizeof(struct udphdr));
                    uint32_t ack = ntohl(recv_rudph->ack_num);
                    
                    if (recv_rudph->flags & FLAG_ACK) {
                        if (verbose) printf("[-] ACK cumulativo recebido: %u\n", ack);
                        metric_acks_recv++;
                        
                        // Atualiza a base_seq e libera os slots confirmados (Orientado a bytes)
                        if (SEQ_GT(ack, base_seq)) {
                            base_seq = ack;
                            for (int i = 0; i < max_slots; i++) {
                                if (window[i].active && SEQ_GE(base_seq, window[i].seq_num + window[i].payload_len)) {
                                    window[i].active = 0; // Segmento totalmente acked
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Timeout e Retransmissão
        long long now = get_time_ms();
        for (int i = 0; i < max_slots; i++) {
            if (window[i].active && (now - window[i].send_time) > timeout_ms) {
                if (verbose) printf("[!] Timeout seq=%u. Retransmitindo pacote de len=%d...\n", window[i].seq_num, window[i].payload_len);
                sendto(sock, window[i].packet, window[i].packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                window[i].send_time = now;
                metric_total_sent++;
                metric_retransmits++;
            }
        }
    }

    // Finaliza (FIN)
    if (verbose) printf(">>> Enviando FIN...\n");
    char fin_packet[128];
    struct udphdr *udph = (struct udphdr *)fin_packet;
    rudp_header_t *rudph = (rudp_header_t *)(fin_packet + sizeof(struct udphdr));
    
    udph->source = htons(12345);
    udph->dest = htons(target_port);
    udph->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t));
    udph->check = 0;
    rudph->seq_num = htonl(next_seq);
    rudph->ack_num = 0;
    rudph->window = htons(window_size_bytes > 65535 ? 65535 : window_size_bytes);
    rudph->length = 0;
    rudph->flags = FLAG_FIN;
    rudph->padding = 0;
    rudph->checksum = 0;
    rudph->checksum = calculate_checksum(rudph, sizeof(rudp_header_t));

    sendto(sock, fin_packet, sizeof(struct udphdr) + sizeof(rudp_header_t), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    long long end_time = get_time_ms();
    printf("\n--- MÉTRICAS ---\nTempo: %.3fs | Enviados: %ld | Reenvios: %ld | ACKs: %ld\n", 
           (end_time - start_time) / 1000.0, metric_total_sent, metric_retransmits, metric_acks_recv);
    
    fclose(file);
    free(window);
    close(sock);
    print_hash(filename);
    return 0;
}