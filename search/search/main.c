#define _CRT_SECURE_NO_WARNINGS

#include <gtk/gtk.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

GtkWidget* fileEntry1, * fileEntry2, * resultLabel;

void calculate_md5(const char* filename, unsigned char* md5sum) {
    // 이전과 동일한 calculate_md5 함수 사용
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    size_t bytes;
    unsigned char buffer[1024];

    mdctx = EVP_MD_CTX_new();
    md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, md5sum, NULL);

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

void compare_files(GtkWidget* widget, gpointer data) {
    const char* filename1 = gtk_entry_get_text(GTK_ENTRY(fileEntry1));
    const char* filename2 = gtk_entry_get_text(GTK_ENTRY(fileEntry2));

    unsigned char md5sum1[MD5_DIGEST_LENGTH], md5sum2[MD5_DIGEST_LENGTH];
    calculate_md5(filename1, md5sum1);
    calculate_md5(filename2, md5sum2);

    // 두 해시값을 비교하고 결과 출력
    if (memcmp(md5sum1, md5sum2, MD5_DIGEST_LENGTH) == 0) {
        gtk_label_set_text(GTK_LABEL(resultLabel), "두 파일의 MD5 해시값이 일치합니다.");
    }
    else {
        gtk_label_set_text(GTK_LABEL(resultLabel), "두 파일의 MD5 해시값이 일치하지 않습니다.");
    }
}

int main(int argc, char* argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget* window, * vbox, * hbox1, * hbox2, * button;

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "MD5 Hash 비교");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    vbox = gtk_vbox_new(FALSE, 5);

    hbox1 = gtk_hbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox1, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_hseparator_new(), FALSE, FALSE, 5);

    hbox2 = gtk_hbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox2, FALSE, FALSE, 5);

    // 첫번째 파일 경로 입력 엔트리
    fileEntry1 = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox1), gtk_label_new("첫번째 파일 경로: "), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(hbox1), fileEntry1, FALSE, FALSE, 5);

    // 두번째 파일 경로 입력 엔트리
    fileEntry2 = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(hbox2), gtk_label_new("두번째 파일 경로: "), FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(hbox2), fileEntry2, FALSE, FALSE, 5);

    // 비교 버튼
    button = gtk_button_new_with_label("비교");
    gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 5);
    g_signal_connect(button, "clicked", G_CALLBACK(compare_files), NULL);

    // 결과 레이블
    resultLabel = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(vbox), resultLabel, FALSE, FALSE, 5);

    gtk_container_add(GTK_CONTAINER(window), vbox);

    gtk_widget_show_all(window);

    gtk_main();

    return 0;
}