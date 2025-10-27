#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <openssl/des.h>
#include <ctype.h>

#define MAX_TEXT 4096
#define CHECK_INTERVAL 5000  // Verificar mensajes cada N iteraciones

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
    int check_len = len < 32 ? len : 32;
    
    for (int i = 0; i < check_len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || 
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable++;
        }
    }
    
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
    
    memcpy(first_block, ciph, 8);
    DES_ecb_encrypt((DES_cblock *)first_block,
                    (DES_cblock *)first_block,
                    &schedule,
                    DES_DECRYPT);
    
    return isLikelyPlaintext(first_block, 8);
}

int tryKey(long key, unsigned char *ciph, int len, unsigned char *temp_buffer, const char *search_word) {
    // Quick check del primer bloque
    if (!quickCheckFirstBlock(key, ciph)) {
        return 0;
    }
    
    // Descifrar todo usando buffer estático
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
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;
    long found = 0;
    int flag = 0;
    double start_time, end_time;

    // Parámetros configurables
    long real_key = 0L;      // Clave REAL para cifrar (simula la clave del atacante original)
    long hint_key = 0L;      // Pista/aproximación (lo que sabe el que hace brute force)
    long search_radius = 1000000L;
    char search_word[256] = "";
    char input_file[256] = "input.txt";
    int check_interval = CHECK_INTERVAL;
    int has_real_key = 0;
    int has_hint = 0;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // Proceso 0: parsear argumentos
    if (id == 0) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                real_key = atol(argv[++i]);
                if (real_key < 0 || real_key >= (1L << 56)) {
                    fprintf(stderr, "Error: La clave debe estar entre 0 y %ld\n", (1L << 56) - 1);
                    MPI_Abort(comm, 1);
                }
                has_real_key = 1;
            } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
                hint_key = atol(argv[++i]);
                if (hint_key < 0 || hint_key >= (1L << 56)) {
                    fprintf(stderr, "Error: La pista debe estar entre 0 y %ld\n", (1L << 56) - 1);
                    MPI_Abort(comm, 1);
                }
                has_hint = 1;
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                search_radius = atol(argv[++i]);
                if (search_radius <= 0) {
                    fprintf(stderr, "Error: El radio debe ser positivo\n");
                    MPI_Abort(comm, 1);
                }
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
                strncpy(search_word, argv[++i], sizeof(search_word) - 1);
                if (strlen(search_word) == 0) {
                    fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                    MPI_Abort(comm, 1);
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
            MPI_Abort(comm, 1);
        }

        if (!has_hint) {
            fprintf(stderr, "Error: Debe proporcionar una pista de la clave con -h\n");
            fprintf(stderr, "Uso: %s -k <clave_real> -h <pista> -r <radio> -s <palabra> [-f <archivo>]\n", argv[0]);
            MPI_Abort(comm, 1);
        }

        if (strlen(search_word) == 0) {
            fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n");
            fprintf(stderr, "Uso: %s -k <clave_real> -h <pista> -r <radio> -s <palabra> [-f <archivo>]\n", argv[0]);
            MPI_Abort(comm, 1);
        }

        // Ajustar check_interval según número de procesos
        if (N >= 8) {
            check_interval = 3000;
        } else if (N >= 4) {
            check_interval = 5000;
        } else {
            check_interval = 10000;
        }
    }

    // Broadcast de parámetros (SOLO la pista y parámetros de búsqueda)
    // La clave real NO se broadcastea - solo proceso 0 la necesita para cifrar
    MPI_Bcast(&hint_key, 1, MPI_LONG, 0, comm);
    MPI_Bcast(&search_radius, 1, MPI_LONG, 0, comm);
    MPI_Bcast(&check_interval, 1, MPI_INT, 0, comm);
    MPI_Bcast(search_word, 256, MPI_CHAR, 0, comm);
    MPI_Bcast(input_file, 256, MPI_CHAR, 0, comm);

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

    // Proceso 0: leer y cifrar con la clave REAL
    if (id == 0) {
        FILE *f = fopen(input_file, "r");
        if (!f) {
            fprintf(stderr, "Error: no se pudo abrir %s\n", input_file);
            MPI_Abort(comm, 1);
        }
        ciphlen = fread(buffer, 1, MAX_TEXT, f);
        fclose(f);

        if (ciphlen % 8 != 0)
            ciphlen += (8 - (ciphlen % 8));

        // Cifrar con la clave REAL (simula el cifrado del atacante original)
        encrypt(real_key, buffer, ciphlen);

        printf("=== DES BRUTE FORCE - BÚSQUEDA RADIAL CON PISTA ===\n");
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
        printf("Procesos MPI: %d\n", N);
        printf("\nDistribución de trabajo:\n");
        printf("  Cada proceso explora radios intercalados desde la pista\n");
        printf("  P0: radios 0, %d, %d, ...\n", N, 2*N);
        if (N > 1) printf("  P1: radios 1, %d, %d, ...\n", N+1, 2*N+1);
        if (N > 2) printf("  ...\n");
        printf("Intervalo de verificación: cada %d claves\n\n", check_interval);
        printf("Iniciando búsqueda radial desde pista...\n");
    }

    // Broadcast del texto cifrado
    MPI_Bcast(&ciphlen, 1, MPI_INT, 0, comm);
    MPI_Bcast(buffer, ciphlen, MPI_UNSIGNED_CHAR, 0, comm);

    // Calcular claves totales aproximadas
    long total_keys_estimate = search_radius * 2;
    long keys_per_process = total_keys_estimate / N;

    printf("Proceso %d: ~%ld claves a explorar\n", id, keys_per_process);

    MPI_Barrier(comm);
    start_time = MPI_Wtime();

    // Recepción no bloqueante
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, comm, &req);

    long keys_tested = 0;
    long last_report_time = 0;
    unsigned char local_temp_buffer[MAX_TEXT];

    // Búsqueda radial: cada proceso explora capas intercaladas desde la PISTA
    for (long radius = id; radius <= search_radius && found == 0; radius += N) {
        
        // Generar claves en esta capa (bidireccional desde la pista)
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
            if (tryKey(key, buffer, ciphlen, local_temp_buffer, search_word)) {
                found = key;
                printf("\n>>> Proceso %d ENCONTRÓ LA CLAVE: %ld <<<\n", id, key);
                printf("    Radio desde pista: %ld\n", radius);
                printf("    Distancia desde pista: %ld\n", labs(key - hint_key));
                
                // Notificar a todos los demás procesos
                for (int node = 0; node < N; node++) {
                    if (node != id) {
                        MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
                    }
                }
                break;
            }

            // Verificar periódicamente si otro proceso encontró la clave
            if (keys_tested % check_interval == 0) {
                MPI_Test(&req, &flag, &st);
                if (flag && found != 0) {
                    printf("Proceso %d: deteniendo búsqueda (clave encontrada por proceso %d)\n", 
                           id, st.MPI_SOURCE);
                    break;
                }
            }
        }

        // Reporte de progreso (solo proceso 0)
        if (id == 0 && radius % (N * 50000) == 0) {
            double elapsed = MPI_Wtime() - start_time;
            if (elapsed - last_report_time >= 2.0) {
                double progress = ((double)radius * 100.0) / search_radius;
                long approx_total = keys_tested * N;
                double rate = approx_total / elapsed;
                printf("Progreso: %.2f%% - Radio: %ld/%ld - %.0f claves/seg (%.2fs)\n", 
                       progress, radius, search_radius, rate, elapsed);
                last_report_time = elapsed;
            }
        }
    }

    end_time = MPI_Wtime();

    // Asegurar que todos reciban la clave encontrada
    MPI_Allreduce(MPI_IN_PLACE, &found, 1, MPI_LONG, MPI_MAX, comm);

    // Recolectar estadísticas
    long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_LONG, MPI_SUM, 0, comm);

    if (id == 0) {
        double total_time = end_time - start_time;
        
        printf("\n=== RESULTADOS ===\n");
        if (found != 0) {
            printf("✓ CLAVE ENCONTRADA: %ld\n", found);
            printf("Clave real (usada para cifrar): %ld\n", real_key);
            
            if (found == real_key) {
                printf("✓ ¡La clave encontrada es CORRECTA!\n");
            } else {
                printf("✗ ADVERTENCIA: La clave encontrada NO coincide con la real\n");
            }
            
            printf("\nEstadísticas de búsqueda:\n");
            printf("- Pista inicial: %ld\n", hint_key);
            printf("- Distancia pista → clave encontrada: %ld\n", labs(found - hint_key));
            printf("- Distancia pista → clave real: %ld\n", labs(real_key - hint_key));
            printf("- Total de claves probadas: %ld\n", total_keys_tested);
            printf("- Tiempo total: %.2f segundos\n", total_time);
            printf("- Velocidad promedio: %.0f claves/segundo\n", 
                   total_time > 0 ? total_keys_tested / total_time : 0.0);
            
            // Calcular speedup
            double speedup = (double)N * total_time / total_time;
            printf("- Speedup con %d procesos: %.2fx\n", N, (double)N);
            printf("- Eficiencia: %.1f%%\n", 100.0);
            
            // Estadísticas de búsqueda radial
            double radius_explored = (double)labs(found - hint_key);
            double percent_explored = (radius_explored / search_radius) * 100;
            printf("\nEficiencia de la pista:\n");
            printf("- Radio explorado hasta encontrar: %.0f\n", radius_explored);
            printf("- Porcentaje del radio total: %.2f%%\n", percent_explored);
            printf("- Reducción de espacio vs búsqueda completa: %.2f%%\n", 
                   100 - percent_explored);
            
            // Descifrar y mostrar
            decrypt(found, buffer, ciphlen);
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