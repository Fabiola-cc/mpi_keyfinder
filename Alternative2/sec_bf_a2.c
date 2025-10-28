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
    long real_key = 0L;      // Clave REAL para cifrar
    long hint_key = 0L;      // Pista/aproximación para búsqueda
    long search_radius = 1000000L;
    char search_word[256] = "";
    char input_file[256] = "input.txt";
    int has_real_key = 0;
    int has_hint = 0;

    // Parseo de argumentos (solo proceso 0)
    if (id == 0) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                real_key = atol(argv[++i]);
                if (real_key < 0 || real_key >= (1L << 56)) {
                    fprintf(stderr, "Error: La clave debe estar entre 0 y %ld\n", (1L << 56) - 1);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                has_real_key = 1;
            } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
                hint_key = atol(argv[++i]);
                if (hint_key < 0 || hint_key >= (1L << 56)) {
                    fprintf(stderr, "Error: La pista debe estar entre 0 y %ld\n", (1L << 56) - 1);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                has_hint = 1;
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                search_radius = atol(argv[++i]);
                if (search_radius <= 0) {
                    fprintf(stderr, "Error: El radio debe ser positivo\n");
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
                strncpy(search_word, argv[++i], sizeof(search_word) - 1);
                if (strlen(search_word) == 0) {
                    fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
            } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
                strncpy(input_file, argv[++i], sizeof(input_file) - 1);
            }
        }

        // Validar parámetros obligatorios
        if (!has_real_key) {
            fprintf(stderr, "Error: Debe proporcionar la clave real con -k\n");
            fprintf(stderr, "Uso: %s -k <clave_real> -h <pista> -r <radio> -s <palabra> [-f <archivo>]\n", argv[0]);
            fprintf(stderr, "\n-k <clave_real>: La clave REAL usada para cifrar el archivo\n");
            fprintf(stderr, "-h <pista>:      Aproximación/pista de donde podría estar la clave\n");
            fprintf(stderr, "-r <radio>:      Radio de búsqueda alrededor de la pista\n");
            fprintf(stderr, "-s <palabra>:    Palabra que debe aparecer en el texto descifrado\n");
            fprintf(stderr, "-f <archivo>:    Archivo de entrada (default: input.txt)\n");
            fprintf(stderr, "\nEjemplo: %s -k 123456 -h 120000 -r 10000 -s \"secret\"\n", argv[0]);
            fprintf(stderr, "  Cifra con clave 123456, busca desde 120000 ±10000\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        if (!has_hint) {
            fprintf(stderr, "Error: Debe proporcionar una pista de la clave con -h\n");
            fprintf(stderr, "Uso: %s -k <clave_real> -h <pista> -r <radio> -s <palabra> [-f <archivo>]\n", argv[0]);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        if (strlen(search_word) == 0) {
            fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n");
            fprintf(stderr, "Uso: %s -k <clave_real> -h <pista> -r <radio> -s <palabra> [-f <archivo>]\n", argv[0]);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }

    // Broadcast de parámetros (solo la pista, no la clave real)
    MPI_Bcast(&hint_key, 1, MPI_LONG, 0, MPI_COMM_WORLD);
    MPI_Bcast(&search_radius, 1, MPI_LONG, 0, MPI_COMM_WORLD);
    MPI_Bcast(search_word, 256, MPI_CHAR, 0, MPI_COMM_WORLD);

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

    // Proceso 0: leer y cifrar con la clave REAL
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

        // Cifrar con la clave REAL
        encrypt(real_key, buffer, ciphlen);

        printf("=== DES BRUTE FORCE SECUENCIAL - BÚSQUEDA RADIAL CON PISTA ===\n");
        printf("\n[SIMULACIÓN]\n");
        printf("Clave REAL usada para cifrar: %ld\n", real_key);
        printf("(En un ataque real, esta clave es desconocida)\n");
        printf("\n[PARÁMETROS DE BÚSQUEDA]\n");
        printf("Pista proporcionada: %ld\n", hint_key);
        printf("Distancia de la pista a la clave real: %ld\n", labs(real_key - hint_key));
        printf("Radio de búsqueda: %ld\n", search_radius);
        printf("Rango de exploración: [%ld, %ld]\n", 
               hint_key - search_radius, 
               hint_key + search_radius);
        
        // Verificar si la clave está en el rango
        if (real_key >= hint_key - search_radius && real_key <= hint_key + search_radius) {
            printf("✓ La clave ESTÁ dentro del rango de búsqueda\n");
        } else {
            printf("✗ ADVERTENCIA: La clave NO está en el rango de búsqueda\n");
            printf("  Necesitarás un radio mayor o una mejor pista\n");
        }
        
        printf("\nEspacio de búsqueda: ~%ld claves\n", search_radius * 2);
        printf("Palabra de búsqueda: \"%s\"\n", search_word);
        printf("Archivo: %s (%d bytes)\n", input_file, ciphlen);
        printf("Procesos MPI: %d (SECUENCIAL - solo proceso 0 trabajará)\n", N);
        printf("\nEstrategia: Búsqueda radial secuencial desde la pista\n");
        printf("  Se explorarán radios: 0, 1, 2, 3, ..., %ld\n", search_radius);
        printf("  Cada radio prueba: pista-radio y pista+radio\n\n");
        printf("Iniciando búsqueda radial secuencial...\n\n");
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
    double last_report_time = 0;

    // BÚSQUEDA SECUENCIAL: Solo proceso 0 trabaja
    if (id == 0) {
        // Búsqueda radial secuencial
        for (long radius = 0; radius <= search_radius && found == 0; radius++) {
            
            // Generar claves en esta capa
            long keys_in_layer[2];
            int valid_keys = 0;

            // Lado negativo (pista - radio)
            long key_minus = hint_key - radius;
            if (key_minus >= 0 && key_minus < (1L << 56)) {
                keys_in_layer[valid_keys++] = key_minus;
            }

            // Lado positivo (pista + radio), evitar duplicado en radius=0
            if (radius > 0) {
                long key_plus = hint_key + radius;
                if (key_plus >= 0 && key_plus < (1L << 56)) {
                    keys_in_layer[valid_keys++] = key_plus;
                }
            }

            // Probar claves en esta capa
            for (int k = 0; k < valid_keys && found == 0; k++) {
                long key = keys_in_layer[k];
                keys_tested++;

                // Probar la clave
                if (tryKey(key, buffer, ciphlen, temp_buffer, search_word)) {
                    found = key;
                    printf("\n>>> CLAVE ENCONTRADA: %ld (radio: %ld) <<<\n", key, radius);
                    break;
                }
            }

            // Reporte de progreso (cada 50000 radios o cada 2 segundos)
            if (radius % 50000 == 0) {
                double elapsed = MPI_Wtime() - start_time;
                if (elapsed - last_report_time >= 2.0) {
                    double progress = ((double)radius * 100.0) / search_radius;
                    double rate = keys_tested / elapsed;
                    printf("Progreso: %.2f%% - Radio: %ld/%ld - %.0f claves/seg (%.2fs)\n", 
                           progress, radius, search_radius, rate, elapsed);
                    last_report_time = elapsed;
                }
            }
        }
    } else {
        // Los demás procesos no hacen nada (ejecución secuencial)
        // Solo esperan en la barrera final
    }

    MPI_Barrier(MPI_COMM_WORLD);
    end_time = MPI_Wtime();

    // Reducción final
    long global_found;
    MPI_Reduce(&found, &global_found, 1, MPI_LONG, MPI_MAX, 0, MPI_COMM_WORLD);
    
    long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_LONG, MPI_SUM, 0, MPI_COMM_WORLD);

    if (id == 0) {
        double total_time = end_time - start_time;
        
        printf("\n=== RESULTADOS (SECUENCIAL) ===\n");
        if (global_found != 0) {
            printf("✓ CLAVE ENCONTRADA: %ld\n", global_found);
            printf("Clave real (usada para cifrar): %ld\n", real_key);
            
            if (global_found == real_key) {
                printf("✓ ¡La clave encontrada es CORRECTA!\n");
            } else {
                printf("✗ ADVERTENCIA: La clave encontrada NO coincide con la real\n");
            }
            
            printf("\nEstadísticas de búsqueda:\n");
            printf("- Pista inicial: %ld\n", hint_key);
            printf("- Distancia pista → clave encontrada: %ld\n", labs(global_found - hint_key));
            printf("- Distancia pista → clave real: %ld\n", labs(real_key - hint_key));
            printf("- Total de claves probadas: %ld\n", total_keys_tested);
            printf("- Tiempo total: %.2f segundos\n", total_time);
            printf("- Velocidad promedio: %.0f claves/segundo\n", 
                   total_time > 0 ? total_keys_tested / total_time : 0.0);
            
            // Estadísticas de búsqueda radial
            double radius_explored = (double)labs(global_found - hint_key);
            double percent_explored = (radius_explored / search_radius) * 100;
            printf("\nEficiencia de la pista:\n");
            printf("- Radio explorado hasta encontrar: %.0f\n", radius_explored);
            printf("- Porcentaje del radio total: %.2f%%\n", percent_explored);
            printf("- Reducción de espacio vs búsqueda completa: %.2f%%\n", 
                   100 - percent_explored);
            
            // Descifrar y mostrar
            decrypt(global_found, buffer, ciphlen);
            buffer[ciphlen] = 0;
            printf("\n--- Texto descifrado ---\n%s\n", buffer);
            printf("------------------------\n");
        } else {
            printf("✗ No se encontró la clave en el radio especificado\n");
            printf("Pista usada: %ld\n", hint_key);
            printf("Radio explorado: %ld\n", search_radius);
            printf("Rango explorado: [%ld, %ld]\n", 
                   hint_key - search_radius, 
                   hint_key + search_radius);
            printf("Clave real: %ld\n", real_key);
            printf("Total de claves probadas: %ld\n", total_keys_tested);
            printf("Tiempo total: %.2f segundos\n", total_time);
            printf("Velocidad: %.0f claves/segundo\n", 
                   total_time > 0 ? total_keys_tested / total_time : 0.0);
            printf("\nSugerencias:\n");
            printf("- Incremente el radio de búsqueda con -r\n");
            printf("- Ajuste la pista con -h para estar más cerca de %ld\n", real_key);
        }
    }

    MPI_Finalize();
    return 0;
}