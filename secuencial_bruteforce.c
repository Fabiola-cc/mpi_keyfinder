#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/des.h>
#include <stdint.h>

// Estructura para almacenar resultados
typedef struct {
    uint64_t key_found;
    double time_elapsed;
    unsigned long long attempts;
    int success;
} BruteForceResult;

// Función para imprimir una clave en formato hexadecimal
void print_key(uint64_t key) {
    printf("0x%016llX", (unsigned long long)key);
}

// Función para imprimir datos en hexadecimal
void print_hex(const char* label, unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Función para cifrar con DES
void des_encrypt(unsigned char* plaintext, unsigned char* ciphertext, 
                 uint64_t key_value) {
    DES_cblock key;
    DES_key_schedule schedule;
    
    // Convertir key_value a DES_cblock
    for (int i = 0; i < 8; i++) {
        key[i] = (key_value >> (56 - i * 8)) & 0xFF;
    }
    
    // Establecer paridad de bits
    DES_set_odd_parity(&key);
    
    // Crear el schedule de la clave
    DES_set_key_unchecked(&key, &schedule);
    
    // Cifrar
    DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)ciphertext, 
                    &schedule, DES_ENCRYPT);
}

// Función para descifrar con DES
void des_decrypt(unsigned char* ciphertext, unsigned char* decrypted, 
                 uint64_t key_value) {
    DES_cblock key;
    DES_key_schedule schedule;
    
    // Convertir key_value a DES_cblock
    for (int i = 0; i < 8; i++) {
        key[i] = (key_value >> (56 - i * 8)) & 0xFF;
    }
    
    // Establecer paridad de bits
    DES_set_odd_parity(&key);
    
    // Crear el schedule de la clave
    DES_set_key_unchecked(&key, &schedule);
    
    // Descifrar
    DES_ecb_encrypt((DES_cblock*)ciphertext, (DES_cblock*)decrypted, 
                    &schedule, DES_DECRYPT);
}

// Función de fuerza bruta secuencial con longitud de clave variable
BruteForceResult brute_force_sequential(unsigned char* ciphertext, 
                                        unsigned char* known_plaintext,
                                        int key_bits) {
    BruteForceResult result = {0, 0.0, 0, 0};
    unsigned char decrypted[8];
    
    // Calcular el espacio de búsqueda
    uint64_t max_key = (1ULL << key_bits) - 1;
    
    printf("\nIniciando búsqueda de fuerza bruta\n");
    printf("Bits de clave: %d\n", key_bits);
    printf("Espacio de búsqueda: %lu claves\n", max_key + 1);
    
    clock_t start = clock();
    
    // Probar todas las claves posibles
    for (uint64_t key = 0; key <= max_key; key++) {
        // Descifrar con la clave actual
        des_decrypt(ciphertext, decrypted, key);
        
        result.attempts++;
        
        // Verificar si coincide con el texto plano conocido
        if (memcmp(decrypted, known_plaintext, 8) == 0) {
            result.key_found = key;
            result.success = 1;
            break;
        }
        
        // Mostrar progreso cada millón de intentos
        if (key > 0 && key % 1000000 == 0) {
            printf("Progreso: %llu claves probadas...\n", 
                   (unsigned long long)key);
        }
    }
    
    clock_t end = clock();
    result.time_elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    return result;
}

// Función para ejecutar pruebas con diferentes longitudes de clave
void run_tests() {
    unsigned char plaintext[8] = "HOLA123";  // 7 caracteres + padding
    unsigned char ciphertext[8];
    
    // Diferentes longitudes de clave a probar (en bits)
    int key_lengths[] = {8, 12, 16, 20, 24};
    int num_tests = sizeof(key_lengths) / sizeof(key_lengths[0]);
    BruteForceResult allResults[num_tests];
    
    printf("PRUEBA DE FUERZA BRUTA SECUENCIAL - DES\n");
    
    printf("\nTexto plano original: ");
    print_hex("", plaintext, 8);
    
    // Resultados de todas las pruebas
    printf("RESULTADOS DE PRUEBAS\n");
    
    for (int i = 0; i < num_tests; i++) {
        int bits = key_lengths[i];
        
        // Generar una clave aleatoria dentro del rango de bits
        uint64_t original_key = rand() % (1ULL << bits);
        
        printf("\nPrueba %d: Clave de %d bits\n", i + 1, bits);
        printf("Clave original: ");
        print_key(original_key);
        printf("\n");
        
        // Cifrar con la clave original
        des_encrypt(plaintext, ciphertext, original_key);
        print_hex("Texto cifrado", ciphertext, 8);
        
        // Realizar ataque de fuerza bruta
        BruteForceResult result = brute_force_sequential(ciphertext, plaintext, bits);
        allResults[i] = result;
        
        // Mostrar resultados
        printf("\nResultados\n");
        if (result.success) {
            printf("✓ Clave encontrada: ");
            print_key(result.key_found);
            printf("\n");
            
            // Verificar que sea correcta
            unsigned char verify[8];
            des_decrypt(ciphertext, verify, result.key_found);
            print_hex("Texto descifrado", verify, 8);
            
            if (memcmp(verify, plaintext, 8) == 0) {
                printf("✓ Verificación exitosa: el texto descifrado coincide\n");
            }
        } else {
            printf("✗ Clave no encontrada\n");
        }
        
        printf("Intentos realizados: %llu\n", result.attempts);
        printf("Tiempo transcurrido: %.6f segundos\n", result.time_elapsed);
        
        if (result.time_elapsed > 0) {
            printf("Velocidad: %.2f claves/segundo\n", 
                   result.attempts / result.time_elapsed);
        }
        
        printf("\n");
    }
    
    // Tabla resumen
    printf("╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                            RESUMEN DE PRUEBAS                              ║\n");
    printf("╠════════════╦═══════════════╦═══════════════╦══════════════════╦════════════╣\n");
    printf("║ Bits Clave ║ Espacio Búsq. ║ Tiempo (seg)  ║ Claves/segundo   ║ Descifrado ║\n");
    printf("╠════════════╬═══════════════╬═══════════════╬══════════════════╬════════════╣\n");
    
    for (int i = 0; i < num_tests; i++) {
        int bits = key_lengths[i];
        uint64_t space = (1ULL << bits);
        
        BruteForceResult result = allResults[i];

        printf("║ %10d ║ %13lu ║ %13.6f ║ %16.2f ║ %10s ║\n", 
               bits, space, result.time_elapsed, 
               result.attempts / (result.time_elapsed > 0 ? result.time_elapsed : 1),
                result.success == 1 ? "si": "no");
    }
    
    printf("╚════════════╩═══════════════╩═══════════════╩══════════════════╩════════════╝\n");
}

// Función principal
int main() {
    // Inicializar generador de números aleatorios
    srand(time(NULL));
    
    printf("\n");
    
    printf("  ATAQUE DE FUERZA BRUTA SECUENCIAL AL ALGORITMO DES\n");
    printf("\nNOTA: DES usa claves de 56 bits efectivos, pero para fines\n");
    printf("educativos, este programa prueba con longitudes reducidas.\n");
    
    // Ejecutar pruebas
    run_tests();
    
    return 0;
}