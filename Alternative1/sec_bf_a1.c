#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <ctype.h>
#include <time.h>

#define MAX_TEXT 4096
#define CHECK_INTERVAL 10000  // Revisar cada N iteraciones

// Buffer estático
static unsigned char temp_buffer_global[MAX_TEXT];

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

int tryKey(long key, unsigned char *ciph, int len, unsigned char *temp_buffer, const char *search_word) {
    // Quick check
    if (!quickCheckFirstBlock(key, ciph)) {
        return 0; // Descarta
    }
    
    DES_cblock keyblock;
    DES_key_schedule schedule;
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    // Copiar al buffer local (se asume len <= MAX_TEXT)
    memcpy(temp_buffer, ciph, len);
    
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(temp_buffer + i),
                        (DES_cblock *)(temp_buffer + i),
                        &schedule,
                        DES_DECRYPT);
    }
    
    temp_buffer[len] = 0;

    // Buscar palabra clave
    return strstr((char *)temp_buffer, search_word) != NULL;
}

int main(int argc, char *argv[]) {
    int N = 1;         // procesos (secuencial)
    int id = 0;        // id del proceso (secuencial)
    long found = 0;
    double start_time, end_time;

    // Parámetros configurables
    long known_key = 123456L;
    char search_word[256] = "";
    char input_file[256] = "input.txt";
    
    // Parámetros automáticos del sistema
    int check_interval = CHECK_INTERVAL;

    // Parseo de argumentos (solo por id==0 en tu versión original)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { // Llave de cifrado
            known_key = atol(argv[++i]);
            if (known_key <= 0) {
                fprintf(stderr, "Error: La clave debe ser un número positivo\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) { // Palabra clave
            strncpy(search_word, argv[++i], sizeof(search_word) - 1);
            if (strlen(search_word) == 0) {
                fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { // Archivo
            strncpy(input_file, argv[++i], sizeof(input_file) - 1);
        }
    }

    if (strlen(search_word) == 0) {
        fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n\n");
        return 1;
    }

    if (N >= 8) {
        check_interval = 5000;
    } else if (N >= 4) {
        check_interval = 10000;
    } else {
        check_interval = 20000;
    }

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

    // Leer archivo y cifrar
    FILE *f = fopen(input_file, "r");
    if (!f) {
        fprintf(stderr, "Error: no se pudo abrir %s\n", input_file);
        return 1;
    }
    ciphlen = fread(buffer, 1, MAX_TEXT, f);
    fclose(f);

    // Ajustar tamaño a múltiplo de 8
    if (ciphlen % 8 != 0)
        ciphlen += (8 - (ciphlen % 8));

    // Cifrar con clave dada por el usuario
    encrypt(known_key, buffer, ciphlen);

    printf("DES BRUTE FORCE SECUENCIAL\n");
    printf("Clave usada para cifrar: %-30ld\n", known_key);
    printf("Palabra de búsqueda: \"%-33s\"\n", search_word);
    printf("Archivo de entrada: %-35s\n", input_file);

    // Calcular rango centrado en la clave
    uint64_t upper = 1ULL << 56; // 2^56
    long range_per_node = upper / N;
    long mylower = range_per_node * id;
    long myupper = (id == N - 1) ? upper : range_per_node * (id + 1);

    printf("Rango de búsqueda total: %ld\n", upper);
    printf("Iniciando búsqueda...\n\n");

    printf("Proceso %d: rango [%ld, %ld] - %ld claves\n", 
           id, mylower, myupper, myupper - mylower);

    // Sincronización no necesaria en secuencial
    start_time = (double)clock() / CLOCKS_PER_SEC;

    long keys_tested = 0;
    long last_report = mylower;
    unsigned char temp_buffer[MAX_TEXT];

    for (long key = mylower; key < myupper && found == 0; key++) {
        keys_tested++;

        if (tryKey(key, buffer, ciphlen, temp_buffer, search_word)) {
            found = key;
            printf("¡Clave encontrada: %ld!\n", key);
            break;
        }
        
        if (keys_tested % check_interval == 0) {
            // Reporte de progreso cada 500k claves (aprox)
            if ((key - last_report) >= 500000) {
                double elapsed = (double)clock() / CLOCKS_PER_SEC - start_time;
                long total_keys = (key - mylower) * N; // aproximado
                double rate = (elapsed > 0.0) ? total_keys / elapsed : 0.0;
                double percent = ((double)key * 100.0) / (double)upper;
                printf("Progreso: %.2f%% - %.0f claves/seg (%.2f segundos)\n", 
                       percent, rate, elapsed);
                last_report = key;
            }
        }
    }

    end_time = (double)clock() / CLOCKS_PER_SEC;

    long total_keys_tested = keys_tested;

    printf("\nRESULTADOS \n");
    double total_time = end_time - start_time;
    if (found != 0) {
        printf("Clave encontrada: %ld\n", found);
        printf("Total de claves probadas: %ld\n", total_keys_tested);
        printf("Tiempo total: %.2f segundos\n", total_time);
        printf("Velocidad: %.0f claves/segundo\n", (total_time > 0.0) ? (total_keys_tested / total_time) : 0.0);
        printf("Speedup con %d procesos: %.2fx\n", N, 
               (total_keys_tested / total_time) / ((total_keys_tested / (total_time * N))));
        
        // Descifrar y mostrar
        decrypt(found, buffer, ciphlen);
        buffer[ciphlen] = 0;
        printf("\nTexto descifrado:\n%s\n", buffer);
    } else {
        printf("No se encontró la clave en el rango especificado.\n");
        printf("Tiempo total: %.2f segundos\n", total_time);
    }

    return 0;
}
