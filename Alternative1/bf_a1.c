#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <openssl/des.h>
#include <ctype.h>

#define MAX_TEXT 4096
#define SEARCH_WORD " the "
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
    int N, id;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;
    long found = 0;
    int flag = 0;
    double start_time, end_time;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    unsigned char buffer[MAX_TEXT];
    int ciphlen = 0;

    if (id == 0) {
        FILE *f = fopen("input.txt", "r");
        if (!f) {
            fprintf(stderr, "Error: no se pudo abrir input.txt\n");
            MPI_Abort(comm, 1);
        }
        ciphlen = fread(buffer, 1, MAX_TEXT, f);
        fclose(f);

        // Ajustar tamaño a múltiplo de 8
        if (ciphlen % 8 != 0)
            ciphlen += (8 - (ciphlen % 8));

        long known_key = 1234567L;
        encrypt(known_key, buffer, ciphlen);
        printf("Procesos MPI: %d\n", N);
        printf("Texto cifrado con clave: %ld\n", known_key);
        printf("Tamaño del texto: %d bytes\n", ciphlen);
    }

    // Broadcast del tamaño y del texto cifrado
    MPI_Bcast(&ciphlen, 1, MPI_INT, 0, comm);
    MPI_Bcast(buffer, ciphlen, MPI_UNSIGNED_CHAR, 0, comm);

    long upper = (1L << 24);  // usar 2^24 para prueba (luego puedes subir a 2^56)
    long range_per_node = upper / N;
    long mylower = range_per_node * id;
    long myupper = (id == N - 1) ? upper : range_per_node * (id + 1);

    if (id == 0) {
        printf("Rango de búsqueda total: [0, %ld]\n", upper);
        printf("Iniciando búsqueda...\n\n");
    }

    // Cada proceso imprime su rango
    printf("Proceso %d: rango [%ld, %ld) - %ld claves\n", 
           id, mylower, myupper, myupper - mylower); //DEBUG

    MPI_Barrier(comm); // Sincronizar antes de empezar

    start_time = MPI_Wtime();

    // Recepción no bloqueante para detectar cuando otro proceso encuentra la clave
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, comm, &req);

    long keys_tested = 0;
    long last_report = mylower;

    for (long key = mylower; key < myupper && found == 0; key++) {
        keys_tested++;
        
        if (tryKey(key, buffer, ciphlen)) {
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
                double total_keys = (key - mylower) * N; // Aproximado
                double rate = total_keys / elapsed;
                double percent = (key * 100.0) / upper;
                printf("Progreso: %.2f%% - %.0f claves/seg (%.2f segundos)\n", 
                       percent, rate, elapsed);
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
        
        printf("\n=== RESULTADOS ===\n");
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