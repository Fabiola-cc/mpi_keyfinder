#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <openssl/des.h>
#include <ctype.h>

#define MAX_TEXT 4096
#define CHECK_INTERVAL 10000  // Revisar si otro proceso encontró la clave cada N iteraciones

// Buffer estático para evitar allocaciones repetidas (thread-local para MPI)
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

int tryKey(long key, unsigned char *ciph, int len, 
                    unsigned char *temp_buffer, const char *search_word) {
    DES_cblock keyblock;
    DES_key_schedule schedule;
    unsigned char first_block[8];
    
    // Setup key UNA SOLA VEZ
    memcpy(&keyblock, &key, 8);
    DES_set_odd_parity(&keyblock);
    DES_set_key_unchecked(&keyblock, &schedule);
    
    // Quick check del primer bloque
    memcpy(first_block, ciph, 8);
    DES_ecb_encrypt((DES_cblock *)first_block,
                    (DES_cblock *)first_block,
                    &schedule,
                    DES_DECRYPT);
    
    if (!isLikelyPlaintext(first_block, 8)) {
        return 0;  // Descarta sin descifrar todo
    }
    
    // Si pasa, descifrar el resto (reutilizando schedule)
    memcpy(temp_buffer, ciph, len);
    memcpy(temp_buffer, first_block, 8);  // Ya tenemos el primer bloque
    
    for (int i = 8; i < len; i += 8) {  // Empezar desde bloque 2
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
    long known_key = 123456L;
    char search_word[256] = "";
    char input_file[256] = "input.txt";
    
    // Parámetros automáticos del sistema
    int check_interval = CHECK_INTERVAL;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    if (id == 0) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) { // Llave de cifrado
                known_key = atol(argv[++i]);
                if (known_key <= 0) { // Validación de clave válida
                    fprintf(stderr, "Error: La clave debe ser un número positivo\n");
                    MPI_Abort(comm, 1);
                }
            } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) { // Palabras clave a buscar en descifrado
                strncpy(search_word, argv[++i], sizeof(search_word) - 1);
                if (strlen(search_word) == 0) { // Validación de que exita la palabra
                    fprintf(stderr, "Error: La palabra de búsqueda no puede estar vacía\n");
                    MPI_Abort(comm, 1);
                }
            } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { // Archivo con texto a cifrar (opcional)
                strncpy(input_file, argv[++i], sizeof(input_file) - 1);
            }
        }

        if (strlen(search_word) == 0) {// Validar presencia de parámetro
            fprintf(stderr, "Error: Debe proporcionar palabra de búsqueda con -s\n\n");
            MPI_Abort(comm, 1);
        }

        // Ajustar check_interval basado en número de procesos
        if (N >= 8) {
            check_interval = 5000;  // Más frecuente con muchos procesos
        } else if (N >= 4) {
            check_interval = 10000;
        } else {
            check_interval = 20000;  // Menos frecuente con pocos procesos
        }
    }

    // Broadcast de todos los parámetros
    MPI_Bcast(&known_key, 1, MPI_LONG, 0, comm);
    MPI_Bcast(&check_interval, 1, MPI_INT, 0, comm);
    MPI_Bcast(search_word, 256, MPI_CHAR, 0, comm);
    MPI_Bcast(input_file, 256, MPI_CHAR, 0, comm);

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

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

        encrypt(known_key, buffer, ciphlen);
        printf("DES BRUTE FORCE MPI\n");
        printf("Clave usada para cifrar: %-30ld\n", known_key);
        printf("Palabra de búsqueda: \"%-33s\"\n", search_word);
        printf("Archivo de entrada: %-35s\n", input_file);
    }

    MPI_Bcast(&ciphlen, 1, MPI_INT, 0, comm);
    MPI_Bcast(buffer, ciphlen, MPI_UNSIGNED_CHAR, 0, comm);

    // Asignar rango de búsqueda a cada proceso
    uint64_t upper = 1ULL << 56; // 2^56
    long range_per_node = upper / N;
    long mylower = range_per_node * id;
    long myupper = (id == N - 1) ? upper : range_per_node * (id + 1);

    if (id == 0) {
        printf("Rango de búsqueda total: %ld\n", upper);
        printf("Iniciando búsqueda...\n\n");
    }

    // Cada proceso imprime su rango
    printf("Proceso %d: rango [%ld, %ld] - %ld claves\n", 
           id, mylower, myupper, myupper - mylower); //DEBUG

    MPI_Barrier(comm); // Sincronizar antes de empezar

    start_time = MPI_Wtime();

    // Recepción no bloqueante para detectar cuando otro proceso encuentra la clave
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, comm, &req);

    long keys_tested = 0;
    long last_report = mylower;
    unsigned char temp_buffer[MAX_TEXT];

    for (long key = mylower; key < myupper && found == 0; key++) {
        keys_tested++;
        
        if (tryKey(key, buffer, ciphlen, temp_buffer, search_word)) {
            found = key;
            printf("\nProceso %d ENCONTRÓ LA CLAVE: %ld\n", id, key); //DEBUG
            
            // Notificar a todos los demás procesos
            for (int node = 0; node < N; node++) {
                if (node != id) {
                    MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
                }
            }
            break;
        }
        
        // Cada CHECK_INTERVAL iteraciones, verificar si otro proceso encontró la clave
        if (keys_tested % CHECK_INTERVAL == 0) {
            MPI_Test(&req, &flag, &st);
            if (flag && found != 0) {
                printf("Proceso %d: deteniendo búsqueda (clave encontrada por proceso %d)\n", 
                       id, st.MPI_SOURCE);
                break;
            }
            
            // Reporte de progreso cada 500k claves
            if (id == 0 && (key - last_report) >= 500000) {
                double elapsed = MPI_Wtime() - start_time;
                long my_total_keys = (key - mylower);
                long total_keys = my_total_keys * N; // Aproximado

                double rate_process = my_total_keys / elapsed;
                double rate = total_keys / elapsed;
                double percent = (key * 100.0) / upper;

                printf("(%.2f segundos) Proceso 0: %.0f claves/seg | En total: ~%.0f claves/seg\n", 
                        elapsed, rate_process, rate);
                last_report = key;
            }
        }
    }

    end_time = MPI_Wtime();

    // Asegurar que todos reciban la clave encontrada
    MPI_Bcast(&found, 1, MPI_LONG, 0, comm);

    // Recolectar estadísticas de cada proceso
    long total_keys_tested;
    MPI_Reduce(&keys_tested, &total_keys_tested, 1, MPI_LONG, MPI_SUM, 0, comm);

    if (id == 0) {
        double total_time = end_time - start_time;
        
        printf("\nRESULTADOS \n");
        if (found != 0) {
            printf("Clave encontrada: %ld\n", found);
            printf("Total de claves probadas: %ld\n", total_keys_tested);
            printf("Tiempo total: %.2f segundos\n", total_time);
            printf("Velocidad: %.0f claves/segundo\n", total_keys_tested / total_time);
            printf("Speedup con %d procesos: %.2fx\n", N, 
                   (total_keys_tested / total_time) / (total_keys_tested / (total_time * N)));
            
            // Descifrar y mostrar
            decrypt(found, buffer, ciphlen);
            buffer[ciphlen] = 0;
            printf("\nTexto descifrado:\n%s\n", buffer);
        } else {
            printf("No se encontró la clave en el rango especificado.\n");
            printf("Tiempo total: %.2f segundos\n", total_time);
        }
    }

    MPI_Finalize();
    return 0;
}