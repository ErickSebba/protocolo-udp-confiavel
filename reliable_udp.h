/**
 * reliable_udp.h
 * * Implementação de um protocolo de transporte confiável inspirado no TCP.
 * * --- FORMATO DO CABEÇALHO (16 bytes totais, alinhados em múltiplos de 4) ---
 * [0-3]   seq_num  (4 bytes): Número de sequência do primeiro byte do segmento.
 * [4-7]   ack_num  (4 bytes): Número de sequência esperado (ACK cumulativo).
 * [8-9]   window   (2 bytes): Tamanho da janela do receptor (advertised window).
 * [10-11] length   (2 bytes): Comprimento dos dados (payload) no segmento.
 * [12-13] checksum (2 bytes): Checksum 16-bit (cabeçalho RUDP + payload).
 * [14]    flags    (1 byte) : Bits de controle (SYN, FIN, ACK, DAT).
 * [15]    padding  (1 byte) : Preenchimento para alinhar em múltiplos de 4 bytes.
 * ---------------------------------------------------------------------------
 */

 #ifndef RELIABLE_UDP_H
 #define RELIABLE_UDP_H
 
 #include <stdint.h>
 #include <stddef.h>
 
 /* Flags de Controle */
 #define FLAG_SYN 0x01
 #define FLAG_FIN 0x02
 #define FLAG_ACK 0x04
 #define FLAG_DAT 0x08
 
 /* Estrutura do cabeçalho do protocolo */
 #pragma pack(push, 1) // Força alinhamento exato
 typedef struct {
     uint32_t seq_num;
     uint32_t ack_num;
     uint16_t window;
     uint16_t length;
     uint16_t checksum;
     uint8_t  flags;
     uint8_t  padding; // Alinhamento para 16 bytes
 } rudp_header_t;
 #pragma pack(pop)
 
 /**
  * Função utilitária para cálculo de checksum 16-bit (Internet Checksum).
  * Soma em complemento de 1 de palavras de 16 bits.
  */
 static inline uint16_t calculate_checksum(const void *data, size_t length) {
     uint32_t sum = 0;
     const uint16_t *ptr = (const uint16_t *)data;
 
     while (length > 1) {
         sum += *ptr++;
         length -= 2;
     }
 
     // Adiciona o último byte se o tamanho for ímpar
     if (length > 0) {
         uint16_t left = 0;
         *(uint8_t *)&left = *(const uint8_t *)ptr;
         sum += left;
     }
 
     // Adiciona carrys
     while (sum >> 16) {
         sum = (sum & 0xFFFF) + (sum >> 16);
     }
 
     return (uint16_t)(~sum);
 }
 
 #endif // RELIABLE_UDP_H