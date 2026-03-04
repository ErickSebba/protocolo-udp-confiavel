#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include "reliable_udp.h"

#define MAX_BUFFER 2048

#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)

long metric_recv = 0, metric_dropped = 0, metric_corrupted = 0;
long metric_retransmits_detect = 0, metric_acks_sent = 0;

int in_burst = 0, burst_counter = 0;

int should_drop(const char* mode, float p_loss, float alpha, float p_low, float p_high, int burst_len) {
    if (strcmp(mode, "none") == 0) return 0;
    double r = (double)rand() / RAND_MAX;
    if (strcmp(mode, "bernoulli") == 0) return (r < p_loss) ? 1 : 0;
    else if (strcmp(mode, "bimodal") == 0) {
        if (!in_burst) {
            if (r < alpha) { in_burst = 1; burst_counter = 1; return ((double)rand() / RAND_MAX < p_high) ? 1 : 0; }
            return (r < p_low) ? 1 : 0;
        } else {
            burst_counter++;
            if (burst_counter >= burst_len) in_burst = 0;
            return ((double)rand() / RAND_MAX < p_high) ? 1 : 0;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    int listen_port = 8080;
    int rx_window_bytes = 10000; // Anunciará essa janela de bytes nos ACKs
    int handshake_timeout_ms = 500;
    char *outfile = "arquivo_recebido.txt";
    char *loss_model = "none";
    float p_loss = 0.0, alpha = 0.0, p_low = 0.0, p_high = 0.0;
    int burst_len = 0, seed = 42, verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) listen_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-w") == 0) rx_window_bytes = atoi(argv[++i]);
        else if (strcmp(argv[i], "-t") == 0) handshake_timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "-o") == 0) outfile = argv[++i];
        else if (strcmp(argv[i], "--loss-model") == 0) loss_model = argv[++i];
        else if (strcmp(argv[i], "--p-loss") == 0) p_loss = atof(argv[++i]);
        else if (strcmp(argv[i], "--seed") == 0) seed = atoi(argv[++i]);
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else if (strcmp(argv[i], "--bimodal-params") == 0) {
            sscanf(argv[++i], "%f,%f,%f,%d", &alpha, &p_low, &p_high, &burst_len);
        }
    }

    srand(seed);
    printf("Ouvindo porta %d | Win: %dB | Saída: %s\n", listen_port, rx_window_bytes, outfile);

    FILE *file = fopen(outfile, "wb");
    if (!file) { perror("Erro ao abrir arquivo"); exit(1); }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("Erro socket RAW (sudo?)"); exit(1); }

    uint32_t expected_seq = 0;
    uint32_t server_isn = 0;
    struct sockaddr_in client_addr;
    uint16_t client_port = 0;
    int handshake_done = 0;
    struct timeval tv_start, tv_end;
    int first_packet = 1;

    if (verbose) printf(">>> Aguardando SYN...\n");

    while (!handshake_done) {
        char buffer[MAX_BUFFER];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        int n = recvfrom(sock, buffer, MAX_BUFFER, 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n <= 0) continue;

        struct iphdr *iph = (struct iphdr *)buffer;
        int ip_hdr_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr *)(buffer + ip_hdr_len);
        if (ntohs(udph->dest) != listen_port) continue;

        rudp_header_t *rudph = (rudp_header_t *)(buffer + ip_hdr_len + sizeof(struct udphdr));
        int payload_len = ntohs(rudph->length);
        if (payload_len != 0) continue;

        uint16_t rcv_checksum = rudph->checksum;
        rudph->checksum = 0;
        if (rcv_checksum != calculate_checksum(rudph, sizeof(rudp_header_t) + payload_len)) continue;

        if (!(rudph->flags & FLAG_SYN)) continue;

        client_addr = src_addr;
        client_port = ntohs(udph->source);
        expected_seq = ntohl(rudph->seq_num) + 1;

        if (verbose) printf("[-] SYN recebido. Enviando SYN|ACK...\n");

        char synack_pkt[64];
        struct udphdr *synack_udp = (struct udphdr *)synack_pkt;
        rudp_header_t *synack_rudp = (rudp_header_t *)(synack_pkt + sizeof(struct udphdr));

        synack_udp->source = udph->dest;
        synack_udp->dest = udph->source;
        synack_udp->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t));
        synack_udp->check = 0;

        synack_rudp->seq_num = htonl(server_isn);
        synack_rudp->ack_num = htonl(expected_seq);
        synack_rudp->window = htons(rx_window_bytes > 65535 ? 65535 : rx_window_bytes);
        synack_rudp->length = 0;
        synack_rudp->flags = FLAG_SYN | FLAG_ACK;
        synack_rudp->padding = 0;
        synack_rudp->checksum = 0;
        synack_rudp->checksum = calculate_checksum(synack_rudp, sizeof(rudp_header_t));

        while (!handshake_done) {
            sendto(sock, synack_pkt, sizeof(struct udphdr) + sizeof(rudp_header_t), 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr));

            fd_set hs_read_fds;
            FD_ZERO(&hs_read_fds);
            FD_SET(sock, &hs_read_fds);

            struct timeval hs_tv;
            hs_tv.tv_sec = handshake_timeout_ms / 1000;
            hs_tv.tv_usec = (handshake_timeout_ms % 1000) * 1000;

            int hs_ret = select(sock + 1, &hs_read_fds, NULL, NULL, &hs_tv);

            if (hs_ret <= 0) {
                if (verbose) printf("[!] Timeout aguardando ACK do handshake. Retransmitindo SYN|ACK...\n");
                continue;
            }

            char ack_buf[MAX_BUFFER];
            struct sockaddr_in ack_src;
            socklen_t ack_len = sizeof(ack_src);
            int ack_n = recvfrom(sock, ack_buf, MAX_BUFFER, 0, (struct sockaddr*)&ack_src, &ack_len);
            if (ack_n <= 0) continue;

            struct iphdr *ack_iph = (struct iphdr *)ack_buf;
            int ack_ip_hdr_len = ack_iph->ihl * 4;
            struct udphdr *ack_udph = (struct udphdr *)(ack_buf + ack_ip_hdr_len);
            if (ntohs(ack_udph->dest) != listen_port) continue;
            if (ntohs(ack_udph->source) != client_port) continue;

            rudp_header_t *ack_rudph = (rudp_header_t *)(ack_buf + ack_ip_hdr_len + sizeof(struct udphdr));
            int ack_payload_len = ntohs(ack_rudph->length);
            if (ack_payload_len != 0) continue;

            uint16_t ack_checksum = ack_rudph->checksum;
            ack_rudph->checksum = 0;
            if (ack_checksum != calculate_checksum(ack_rudph, sizeof(rudp_header_t) + ack_payload_len)) continue;

            if (ack_rudph->flags & FLAG_ACK) {
                uint32_t ack_num = ntohl(ack_rudph->ack_num);
                uint32_t ack_seq = ntohl(ack_rudph->seq_num);
                if (ack_num == server_isn + 1 && ack_seq == expected_seq) {
                    handshake_done = 1;
                    if (verbose) printf("[-] ACK do handshake recebido. Conexão estabelecida.\n");
                }
            }
        }
    }

    while (1) {
        char buffer[MAX_BUFFER];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        int n = recvfrom(sock, buffer, MAX_BUFFER, 0, (struct sockaddr*)&src_addr, &addr_len);
        if (n <= 0) continue;

        struct iphdr *iph = (struct iphdr *)buffer;
        int ip_hdr_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr *)(buffer + ip_hdr_len);
        if (ntohs(udph->dest) != listen_port) continue;

        rudp_header_t *rudph = (rudp_header_t *)(buffer + ip_hdr_len + sizeof(struct udphdr));
        char *payload = buffer + ip_hdr_len + sizeof(struct udphdr) + sizeof(rudp_header_t);
        int payload_len = ntohs(rudph->length);

        if (!(rudph->flags & (FLAG_DAT | FLAG_FIN))) continue;

        metric_recv++;

        if (should_drop(loss_model, p_loss, alpha, p_low, p_high, burst_len)) {
            metric_dropped++;
            if (verbose) printf("[!] DROP Simulado: Seq=%u\n", ntohl(rudph->seq_num));
            continue;
        }

        uint16_t rcv_checksum = rudph->checksum;
        rudph->checksum = 0;
        if (rcv_checksum != calculate_checksum(rudph, sizeof(rudp_header_t) + payload_len)) {
            metric_corrupted++;
            continue;
        }

        uint32_t seq = ntohl(rudph->seq_num);
        if (first_packet) { gettimeofday(&tv_start, NULL); first_packet = 0; }

        if (rudph->flags & FLAG_FIN) {
            char ack_pkt[64];
            struct udphdr *ack_udp = (struct udphdr *)ack_pkt;
            rudp_header_t *ack_rudp = (rudp_header_t *)(ack_pkt + sizeof(struct udphdr));
            
            ack_udp->source = udph->dest; ack_udp->dest = udph->source;
            ack_udp->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t)); ack_udp->check = 0;
            ack_rudp->seq_num = 0; ack_rudp->ack_num = htonl(expected_seq);
            ack_rudp->window = htons(rx_window_bytes > 65535 ? 65535 : rx_window_bytes); // Adverte janela limite em Bytes
            ack_rudp->length = 0; ack_rudp->flags = FLAG_ACK; ack_rudp->padding = 0; ack_rudp->checksum = 0;
            ack_rudp->checksum = calculate_checksum(ack_rudp, sizeof(rudp_header_t));

            sendto(sock, ack_pkt, sizeof(struct udphdr) + sizeof(rudp_header_t), 0, (struct sockaddr *)&src_addr, sizeof(src_addr));
            break;
        }

        if (seq == expected_seq) {
            fwrite(payload, 1, payload_len, file);
            expected_seq += payload_len; // Processo contínuo de bytes
            if (verbose) printf("[+] Recebido seq=%u (len=%d). Esperando agora %u\n", seq, payload_len, expected_seq);
        } else if (SEQ_GT(expected_seq, seq)) {
            metric_retransmits_detect++;
            if (verbose) printf("[~] Duplicado seq=%u\n", seq);
        } else {
            if (verbose) printf("[!] Fora de ordem seq=%u. Esperava %u\n", seq, expected_seq);
        }

        // Envia ACK
        char ack_pkt[64];
        struct udphdr *ack_udp = (struct udphdr *)ack_pkt;
        rudp_header_t *ack_rudp = (rudp_header_t *)(ack_pkt + sizeof(struct udphdr));
        
        ack_udp->source = udph->dest; ack_udp->dest = udph->source;
        ack_udp->len = htons(sizeof(struct udphdr) + sizeof(rudp_header_t)); ack_udp->check = 0;
        ack_rudp->seq_num = 0; 
        ack_rudp->ack_num = htonl(expected_seq);
        ack_rudp->window = htons(rx_window_bytes > 65535 ? 65535 : rx_window_bytes);
        ack_rudp->length = 0; ack_rudp->flags = FLAG_ACK; ack_rudp->padding = 0; ack_rudp->checksum = 0;
        ack_rudp->checksum = calculate_checksum(ack_rudp, sizeof(rudp_header_t));

        sendto(sock, ack_pkt, sizeof(struct udphdr) + sizeof(rudp_header_t), 0, (struct sockaddr *)&src_addr, sizeof(src_addr));
        metric_acks_sent++;
    }

    gettimeofday(&tv_end, NULL);
    printf("\n--- MÉTRICAS ---\nTempo: %.3f s | Recebidos: %ld | Descartados: %ld | Duplicados: %ld\n", 
           (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec) / 1e6, metric_recv, metric_dropped, metric_retransmits_detect);
    fclose(file); close(sock);
    char cmd[512]; snprintf(cmd, sizeof(cmd), "sha256sum %s", outfile); system(cmd);
    return 0;
}