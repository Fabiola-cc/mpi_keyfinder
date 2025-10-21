#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <ctype.h>
#include <time.h>

#define MAX_TEXT 4096
#define SEARCH_WORD " the "

// Buffer estático para evitar allocaciones repetidas
static unsigned char temp_buffer[MAX_TEXT];

void decrypt(long key, unsigned char *ciph, int len) {
    DES_cblock keyblock;
    DES_key_schedule schedule;
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i),
                        (DES_cblock *)(ciph + i),
                        &schedule,
                        DES_DECRYPT);
    }
}

void encrypt(long key, unsigned char *plain, int len) {
    DES_cblock keyblock;
    DES_key_schedule schedule;
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(plain + i),
                        (DES_cblock *)(plain + i),
                        &schedule,
                        DES_ENCRYPT);
    }
}

// Validación rápida: verifica si los bytes parecen texto ASCII válido
int isLikelyPlaintext(unsigned char *data, int len) {
    int printable = 0;
    int check_len = len < 32 ? len : 32; // Solo revisar primeros 32 bytes
    
    for (int i = 0; i < check_len; i++) {
        // Contar caracteres imprimibles (espacio a ~) o whitespace común
        if ((data[i] >= 32 && data[i] <= 126) || 
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable++;
        }
    }
    
    // Si más del 90% parece texto, continuar
    return (printable * 100 / check_len) > 90;
}

// Descifra solo el primer bloque para filtrado rápido
int quickCheckFirstBlock(long key, unsigned char *ciph) {
    DES_cblock keyblock;
    DES_key_schedule schedule;
    unsigned char first_block[8];
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    // Solo descifrar primer bloque
    memcpy(first_block, ciph, 8);
    DES_ecb_encrypt((DES_cblock *)first_block,
                    (DES_cblock *)first_block,
                    &schedule,
                    DES_DECRYPT);
    
    // Verificar si parece texto válido
    return isLikelyPlaintext(first_block, 8);
}

int tryKey(long key, unsigned char *ciph, int len) {
    // Primero: quick check del primer bloque
    if (!quickCheckFirstBlock(key, ciph)) {
        return 0; // Descarta inmediatamente si no parece texto
    }
    
    // Si pasa el quick check, descifrar todo usando buffer estático
    DES_cblock keyblock;
    DES_key_schedule schedule;
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    // Copiar solo una vez al buffer estático
    memcpy(temp_buffer, ciph, len);
    
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(temp_buffer + i),
                        (DES_cblock *)(temp_buffer + i),
                        &schedule,
                        DES_DECRYPT);
    }
    
    temp_buffer[len] = 0;
    
    // Buscar palabra clave
    return strstr((char *)temp_buffer, SEARCH_WORD) != NULL;
}

int main(int argc, char *argv[]) {
    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;
    long found = 0;
    
    // Leer archivo
    FILE *f = fopen("input.txt", "r");
    if (!f) {
        fprintf(stderr, "Error: no se pudo abrir input.txt\n");
        return 1;
    }
    
    ciphlen = fread(buffer, 1, MAX_TEXT, f);
    fclose(f);
    
    // Ajustar tamaño a múltiplo de 8
    if (ciphlen % 8 != 0)
        ciphlen += (8 - (ciphlen % 8));
    
    // Cifrar con clave conocida
    long known_key = 1234567L;
    encrypt(known_key, buffer, ciphlen);
    printf("Texto cifrado con clave: %ld\n", known_key);
    printf("Tamaño del texto: %d bytes\n", ciphlen);
    
    // Búsqueda de fuerza bruta
    long upper = (1L << 24);  // 2^24 para prueba
    printf("Buscando clave en rango [0, %ld]...\n\n", upper);
    
    clock_t start = clock();
    long keys_tested = 0;
    
    for (long key = 0; key < upper && !found; key++) {
        keys_tested++;
        
        if (tryKey(key, buffer, ciphlen)) {
            found = key;
            printf("¡Clave encontrada: %ld!\n", key);
            break;
        }
        
        // Progreso cada 100k claves
        if (key > 0 && key % 100000 == 0) {
            double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
            double rate = keys_tested / elapsed;
            double percent = (key * 100.0) / upper;
            printf("Progreso: %.2f%% - %ld claves probadas - %.0f claves/seg\n", 
                   percent, keys_tested, rate);
        }
    }
    
    clock_t end = clock();
    double total_time = (double)(end - start) / CLOCKS_PER_SEC;
    
    if (found) {
        printf("\nRESULTADO: \n");
        printf("Clave encontrada: %ld\n", found);
        printf("Claves probadas: %ld\n", keys_tested);
        printf("Tiempo total: %.2f segundos\n", total_time);
        printf("Velocidad: %.0f claves/segundo\n", keys_tested / total_time);
        
        // Descifrar y mostrar
        decrypt(found, buffer, ciphlen);
        buffer[ciphlen] = 0;
        printf("\nTexto descifrado:\n%s\n", buffer);
    } else {
        printf("\nNo se encontró la clave en el rango especificado.\n");
        printf("Tiempo total: %.2f segundos\n", total_time);
    }
    
    return 0;
}