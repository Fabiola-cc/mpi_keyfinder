#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <ctype.h>
#include <mpi.h>

#define MAX_TEXT 4096
#define CHECK_INTERVAL 5000
#define TAG_FOUND 100

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

int isLikelyPlaintext(unsigned char *data, int len) {
    int printable = 0;
    int check_len = len < 32 ? len : 32;
    
    for (int i = 0; i < check_len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || 
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable++;
        }
    }
    
    return (printable * 100 / check_len) > 90;
}

int quickCheckFirstBlock(long key, unsigned char *ciph) {
    DES_cblock keyblock;
    DES_key_schedule schedule;
    unsigned char first_block[8];
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    memcpy(first_block, ciph, 8);
    DES_ecb_encrypt((DES_cblock *)first_block,
                    (DES_cblock *)first_block,
                    &schedule,
                    DES_DECRYPT);
    
    return isLikelyPlaintext(first_block, 8);
}

int tryKey(long key, unsigned char *ciph, int len, unsigned char *temp_buffer, const char *search_word) {
    if (!quickCheckFirstBlock(key, ciph)) {
        return 0;
    }
    
    DES_cblock keyblock;
    DES_key_schedule schedule;
    
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    memcpy(temp_buffer, ciph, len);
    
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(temp_buffer + i),
                        (DES_cblock *)(temp_buffer + i),
                        &schedule,
                        DES_DECRYPT);
    }
    
    temp_buffer[len] = 0;
    return strstr((char *)temp_buffer, search_word) != NULL;
}

int main(int argc, char *argv[]) {
    int N, id;
    long found = 0;
    double start_time, end_time;
    MPI_Status status;
    
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &N);
    MPI_Comm_rank(MPI_COMM_WORLD, &id);

    // Parámetros configurables
    long known_key = 123456L;
    long search_radius = 1000000L; // Radio de búsqueda desde la clave conocida
    char search_word[256] = "";
    char input_file[256] = "input.txt";

    // Parseo de argumentos (solo proceso 0)
    if (id == 0) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                known_key = atol(argv[++i]);
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                search_radius = atol(argv[++i]);
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
                strncpy(search_word, argv[++i], sizeof(search_word) - 1);
            } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
                strncpy(input_file, argv[++i], sizeof(input_file) - 1);
            }
        }

        if (strlen(search_word) == 0) {
            fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }

    // Broadcast de parámetros
    MPI_Bcast(&known_key, 1, MPI_LONG, 0, MPI_COMM_WORLD);
    MPI_Bcast(&search_radius, 1, MPI_LONG, 0, MPI_COMM_WORLD);
    MPI_Bcast(search_word, 256, MPI_CHAR, 0, MPI_COMM_WORLD);

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

    // Proceso 0: leer y cifrar
    if (id == 0) {
        FILE *f = fopen(input_file, "r");
        if (!f) {
            fprintf(stderr, "Error: no se pudo abrir %s\n", input_file);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        ciphlen = fread(buffer, 1, MAX_TEXT, f);
        fclose(f);

        if (ciphlen % 8 != 0)
            ciphlen += (8 - (ciphlen % 8));

        encrypt(known_key, buffer, ciphlen);

        printf("=== DES BRUTE FORCE - BÚSQUEDA RADIAL ===\n");
        printf("Estrategia: Exploración concéntrica desde clave conocida\n");
        printf("Clave central: %ld\n", known_key);
        printf("Radio de búsqueda: %ld (rango: [%ld, %ld])\n", 
               search_radius, 
               known_key - search_radius, 
               known_key + search_radius);
        printf("Palabra de búsqueda: \"%s\"\n", search_word);
        printf("Procesos MPI: %d\n", N);
        printf("Distribución: Cada proceso toma capas intercaladas\n");
        printf("  P0: capas 0, %d, %d, ...\n", N, 2*N);
        printf("  P1: capas 1, %d, %d, ...\n", N+1, 2*N+1);
        printf("  ...\n\n");
        printf("Iniciando búsqueda radial...\n\n");
    }

    // Broadcast del texto cifrado
    MPI_Bcast(&ciphlen, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(buffer, ciphlen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    MPI_Barrier(MPI_COMM_WORLD);
    start_time = MPI_Wtime();

    long keys_tested = 0;
    unsigned char temp_buffer[MAX_TEXT];
    int message_available;
    long received_key;

    // Búsqueda radial: cada proceso explora capas intercaladas
    for (long radius = id; radius <= search_radius && found == 0; radius += N) {
        
        // Explorar ambos lados del radio: known_key - radius y known_key + radius
        long keys_in_layer[2];
        int valid_keys = 0;

        // Lado negativo
        long key_minus = known_key - radius;
        if (key_minus >= 0 && key_minus < (1L << 56)) {
            keys_in_layer[valid_keys++] = key_minus;
        }

        // Lado positivo (evitar duplicados en radius=0)
        if (radius > 0) {
            long key_plus = known_key + radius;
            if (key_plus >= 0 && key_plus < (1L << 56)) {
                keys_in_layer[valid_keys++] = key_plus;
            }
        }

        // Probar claves en esta capa
        for (int k = 0; k < valid_keys && found == 0; k++) {
            long key = keys_in_layer[k];
            keys_tested++;

            // Verificar si otro proceso encontró la clave
            if (keys_tested % CHECK_INTERVAL == 0) {
                MPI_Iprobe(MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &message_available, &status);
                if (message_available) {
                    MPI_Recv(&received_key, 1, MPI_LONG, MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &status);
                    found = received_key;
                    break;
                }
            }

            // Probar clave
            if (tryKey(key, buffer, ciphlen, temp_buffer, search_word)) {
                found = key;
                
                // Notificar a todos los demás procesos
                for (int dest = 0; dest < N; dest++) {
                    if (dest != id) {
                        MPI_Send(&found, 1, MPI_LONG, dest, TAG_FOUND, MPI_COMM_WORLD);
                    }
                }
                break;
            }
        }

        // Reporte de progreso
        if (radius % (N * 1000) == id && id == 0) {
            double elapsed = MPI_Wtime() - start_time;
            double progress = ((double)radius * 100.0) / search_radius;
            printf("Progreso: %.2f%% - Radio: %ld/%ld - Tiempo: %.2fs\n", 
                   progress, radius, search_radius, elapsed);
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);
    end_time = MPI_Wtime();

    // Reducción final para obtener la clave encontrada
    long global_found;
    MPI_Reduce(&found, &global_found, 1, MPI_LONG, MPI_MAX, 0, MPI_COMM_WORLD);
    
    long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_LONG, MPI_SUM, 0, MPI_COMM_WORLD);

    if (id == 0) {
        double total_time = end_time - start_time;
        printf("\n=== RESULTADOS ===\n");
        
        if (global_found != 0) {
            printf("✓ Clave encontrada: %ld\n", global_found);
            printf("Distancia desde clave conocida: %ld\n", labs(global_found - known_key));
            printf("Total de claves probadas: %ld\n", total_keys_tested);
            printf("Tiempo total: %.2f segundos\n", total_time);
            printf("Velocidad: %.0f claves/segundo\n", 
                   total_time > 0 ? total_keys_tested / total_time : 0.0);
            printf("Speedup teórico con %d procesos: %.2fx\n", N, (double)N);
            
            // Descifrar y mostrar
            decrypt(global_found, buffer, ciphlen);
            buffer[ciphlen] = 0;
            printf("\n--- Texto descifrado ---\n%s\n", buffer);
            printf("------------------------\n");
        } else {
            printf("✗ No se encontró la clave en el radio especificado\n");
            printf("Radio explorado: %ld\n", search_radius);
            printf("Rango: [%ld, %ld]\n", 
                   known_key - search_radius, 
                   known_key + search_radius);
            printf("Tiempo total: %.2f segundos\n", total_time);
            printf("Sugerencia: Incremente el radio de búsqueda con -r\n");
        }
    }

    MPI_Finalize();
    return 0;
}