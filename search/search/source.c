//해시 계산 및 비교 openssl사용

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <conio.h>

#define BUFFER_SIZE 1024

void calculate_md5(FILE* file, unsigned char* md5sum) {//해시계산 MD5
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    size_t bytes;
    unsigned char buffer[BUFFER_SIZE];

    mdctx = EVP_MD_CTX_new();
    md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes = fread(buffer, 1, BUFFER_SIZE, file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, md5sum, NULL);

    EVP_MD_CTX_free(mdctx);
}

int compare_hashes(const unsigned char* hash1, const unsigned char* hash2) {//해시비교
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (hash1[i] != hash2[i]) {
            return 0;  // 해시값이 다르면 0 반환
        }
    }
    return 1;  // 해시값이 동일하면 1 반환
}

int main() {

    int program = 1;
    char key;

    while(program) {
        char filename_1[256];  // 1번 파일 경로를 저장할 충분한 크기의 배열
        printf("비교할 첫번째 파일 경로를 입력하세요: ");

        // scanf_s 함수에서는 문자열의 크기를 지정해야 합니다.
        // "%s" 형식을 사용하면 최대 문자열 크기 - 1 만큼의 문자열을 받습니다.
        if (scanf_s("%255s", filename_1, sizeof(filename_1)) != 1) {
            perror("Error reading filename");
            return EXIT_FAILURE;
        }

        FILE* file_1 = fopen(filename_1, "rb");

        if (!file_1) {
            perror("Error opening file");
            return EXIT_FAILURE;
        }

        unsigned char md5sum_1[MD5_DIGEST_LENGTH];
        calculate_md5(file_1, md5sum_1);

        fclose(file_1);

        printf("MD5 Hash (%s): ", filename_1);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", md5sum_1[i]);
        }
        printf("\n\n");

        char filename_2[256];//2번 파일 경로를 저장할 배열 선언

        printf("비교할 두번째 파일의 경로를 입력하세요: ");

        if (scanf_s("%255s", filename_2, sizeof(filename_2)) != 1) {
            perror("Error reading filename");
            return EXIT_FAILURE;
        }

        FILE* file_2 = fopen(filename_2, "rb");

        unsigned char md5sum_2[MD5_DIGEST_LENGTH];
        calculate_md5(file_2, md5sum_2);

        fclose(file_2);

        printf("MD5 Hash (%s): ", filename_2);
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", md5sum_2[i]);
        }
        printf("\n\n");

        // 두 해시값을 비교하고 결과 출력
        if (compare_hashes(md5sum_1, md5sum_2) == 1) {
            printf("두 파일의 MD5 해시값이 일치합니다.\n");
        }
        else {
            printf("두 파일의 MD5 해시값이 일치하지 않습니다.\n");
        }
        
        printf("프로그램을 종료하려면 스페이스바를 눌러주세요.\n");
        printf("새로운 검사를 진행하고 싶으면 스페이스바를 제외한 아무 키나 입력하세요.\n");

        key = _getch();

        if (key != ' ')
        {
            printf("\n\n");
            continue;
        }
        else
        {
            return EXIT_SUCCESS;
            break;
        }
    }
    
}
