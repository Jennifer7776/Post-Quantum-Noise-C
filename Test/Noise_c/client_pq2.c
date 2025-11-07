// ===============================
// client_pq2.c — Noise by name + 5-arg keypair; static-vs-ephemeral Follow Handshake Algrithim （TCP）
// Build: gcc -O2 -Wall -Wextra client_pq.c -lnoise -loqs -o client_pq
// Output header: role,pattern,kem,label,iter,latency_ms,rc
// ===============================
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <noise/protocol.h>
#include <oqs/oqs.h>

#define BUF_CAP (65535u + 2u)
static uint8_t message[BUF_CAP];

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s PATTERN LABEL [KEM]\n"
        "       [--iters N] [--warmup W] [--csv|--tsv] [--no-header]\n"
        "       [--host H] [--port P]\n", prog);
}

static double diff_ms(const struct timespec *t0, const struct timespec *t1) {
    const long sec = t1->tv_sec - t0->tv_sec;
    const long nsec = t1->tv_nsec - t0->tv_nsec;
    return (double)sec * 1000.0 + (double)nsec / 1e6;
}

static int load_key_fixed(const char *path, uint8_t *dst, size_t need) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 1;
    size_t r = fread(dst, 1, need, fp);
    fclose(fp);
    return r == need ? 0 : 2;
}

static int load_key_alloc(const char *path, uint8_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) return 1;
    struct stat st; if (stat(path,&st)!=0){ fclose(fp); return 2; }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = (uint8_t*)malloc(sz);
    if(!buf){ fclose(fp); return 3; }
    if(fread(buf,1,sz,fp)!=sz){ fclose(fp); free(buf); return 4; }
    fclose(fp);
    *out = buf; *out_len = sz; return 0;
}

static void kem_tokens(const char *in,
                       char *noise_tok, size_t ncap,
                       char *file_tok1, size_t f1cap,
                       char *file_tok2, size_t f2cap)
{
    char tmp[64]={0}; size_t j=0;
    for (size_t i=0; in && in[i] && j+1<sizeof(tmp); ++i)
        if (in[i]!=' ' && in[i]!='\t') tmp[j++]=in[i];

    if (!strncasecmp(tmp,"kyber",5)) { const char*s=tmp+5;
        snprintf(noise_tok,ncap,"Kyber%s",s);
        snprintf(file_tok1,f1cap,"Kyber%s",s);
        snprintf(file_tok2,f2cap,"Kyber-%s",s);
        return;
    }
    if (!strncasecmp(tmp,"hqc",3)) { const char*s=tmp+3; while(*s=='-'||*s=='_')++s;
        snprintf(noise_tok,ncap,"HQC%s",s);
        snprintf(file_tok1,f1cap,"HQC%s",s);
        snprintf(file_tok2,f2cap,"HQC-%s",s);
        return;
    }
    if (!strncasecmp(tmp,"bike",4)) {
        const char *lvl=NULL,*pL=strcasestr(tmp,"l");
        if(pL&&pL[1]) lvl=pL+1;
        if(!lvl) for(size_t i=0;i<strlen(tmp);++i) if(isdigit((unsigned char)tmp[i])){lvl=tmp+i;break;}
        if(!lvl) lvl="1";
        snprintf(noise_tok,ncap,"BIKEL%s",lvl);
        snprintf(file_tok1,f1cap,"BIKEL%s",lvl);
        snprintf(file_tok2,f2cap,"BIKE-L%s",lvl);
        return;
    }
    char nohy[64]={0}; size_t k=0;
    for(size_t i=0; in && in[i] && k+1<sizeof(nohy); ++i)
        if(in[i]!='-'&&in[i]!='_') nohy[k++]=in[i];
    snprintf(noise_tok,ncap,"%s",nohy);
    snprintf(file_tok1,f1cap,"%s",nohy);
    snprintf(file_tok2,f2cap,"%s",in?in:"");
}

static void kem_to_oqs_name(const char *kem_arg, char *oqs_name, size_t cap){
    char noise_tok[32], f1[32], f2[32];
    kem_tokens(kem_arg, noise_tok, sizeof(noise_tok), f1, sizeof(f1), f2, sizeof(f2));
    if (!strncasecmp(f1,"Kyber",5)) snprintf(oqs_name,cap,"%s",f1);
    else                            snprintf(oqs_name,cap,"%s",f2);
}

static int load_pq_key_multi(const char *role, const char *kem_user,
                             uint8_t **out, size_t *out_len)
{
    char noise_tok[32], f1[32], f2[32], path[160];
    kem_tokens(kem_user, noise_tok, sizeof(noise_tok), f1, sizeof(f1), f2, sizeof(f2));
    snprintf(path,sizeof(path),"./Keys/%s_%s.bin",role,f1);
    if (load_key_alloc(path,out,out_len)==0) return 0;
    snprintf(path,sizeof(path),"./Keys/%s_%s.bin",role,f2);
    if (load_key_alloc(path,out,out_len)==0) return 0;
    snprintf(path,sizeof(path),"./Keys/%s_pq.txt",role);
    if (load_key_alloc(path,out,out_len)==0) return 0;
    return 1;
}

static int role_char_initiator(const char *pattern){
    if (!pattern || !pattern[0]) return 'N';
    int c = (unsigned char)pattern[0];
    if (c>='a'&&c<='z') c-=32;
    return c;
}

// Provide local key: If have_static == 1, then provide a static key; otherwise, generate a temporary key immediately.
static int supply_local_keypair(NoiseHandshakeState *hs,
                                int have_static,
                                const uint8_t *sk, size_t sk_len,
                                const uint8_t *pk, size_t pk_len,
                                const char *oqs_name)
{
    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(hs);
    if (!dh) return NOISE_ERROR_INVALID_STATE;

    if (have_static) {
        return noise_dhstate_set_keypair(dh, sk, sk_len, pk, pk_len);
    } else {
        OQS_KEM *kem = OQS_KEM_new(oqs_name);
        if (!kem) return NOISE_ERROR_INVALID_STATE;
        uint8_t *eph_pk = (uint8_t*)malloc(kem->length_public_key);
        uint8_t *eph_sk = (uint8_t*)malloc(kem->length_secret_key);
        if (!eph_pk || !eph_sk) { if(eph_pk)free(eph_pk); if(eph_sk)free(eph_sk); OQS_KEM_free(kem); return NOISE_ERROR_NO_MEMORY; }
        if (OQS_KEM_keypair(kem, eph_pk, eph_sk) != OQS_SUCCESS) {
            free(eph_pk); free(eph_sk); OQS_KEM_free(kem); return NOISE_ERROR_INVALID_STATE;
        }
        int err = noise_dhstate_set_keypair(dh, eph_sk, kem->length_secret_key,
                                               eph_pk, kem->length_public_key);
        if (eph_sk) memset(eph_sk, 0, kem->length_secret_key);
        free(eph_pk); free(eph_sk); OQS_KEM_free(kem);
        return err;
    }
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (getenv("PQ_WHITEBOX")) setvbuf(stderr, NULL, _IONBF, 0);

    if(argc<3){ usage(argv[0]); return 1; }

    const char *pattern = argv[1];
    const char *label   = argv[2];
    const char *kem_arg = (argc>=4 && strncmp(argv[3],"--",2)!=0) ? argv[3] : "Kyber512";

    int iters  = 1000;
    int warmup = 20;
    int header = 1;
    char sep   = ',';
    const char *host = "127.0.0.1";
    int port = 8888;

    for (int i = 3; i < argc; i++) {
        if (strncmp(argv[i],"--",2)!=0) continue;
        if      (!strcmp(argv[i],"--iters")   && i+1<argc) iters  = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--warmup")  && i+1<argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--csv"))                 sep    = ',';
        else if (!strcmp(argv[i],"--tsv"))                 sep    = '\t';
        else if (!strcmp(argv[i],"--no-header"))           header = 0;
        else if (!strcmp(argv[i],"--host")    && i+1<argc) host   = argv[++i];
        else if (!strcmp(argv[i],"--port")    && i+1<argc) port   = atoi(argv[++i]);
    }
    if (iters <= 0) iters = 1;
    if (warmup < 0) warmup = 0;
    if (warmup > iters) warmup = iters;

    // Fixed (Classic) 32B
    uint8_t client_priv_x25519[32], client_pub_x25519[32], server_pub_x25519[32];
    if (load_key_fixed("./Keys/client_priv.txt", client_priv_x25519, 32)) return 1;
    if (load_key_fixed("./Keys/client_pub.txt",  client_pub_x25519,  32)) return 1;
    if (load_key_fixed("./Keys/server_pub.txt",  server_pub_x25519,  32)) return 1;

    // Peer-side static PQ public key (if needed)
    uint8_t *server_pub_pq=NULL; size_t server_pub_pq_len=0;
    load_pq_key_multi("server_pub", kem_arg, &server_pub_pq, &server_pub_pq_len); // 允许失败

    // Static PQ private/public key (if needed)
    uint8_t *client_priv_pq=NULL,*client_pub_pq=NULL;
    size_t client_priv_pq_len=0, client_pub_pq_len=0;
    load_pq_key_multi("client_priv", kem_arg, &client_priv_pq, &client_priv_pq_len);
    load_pq_key_multi("client_pub",  kem_arg, &client_pub_pq,  &client_pub_pq_len);

    char kem_tok[32], f1[32], f2[32];
    kem_tokens(kem_arg, kem_tok, sizeof(kem_tok), f1, sizeof(f1), f2, sizeof(f2));
    char proto_name[96];
    snprintf(proto_name, sizeof(proto_name),
             "Noise_pq%s_%s_ChaChaPoly_BLAKE2s", pattern, kem_tok);

    char oqs_name[64]; kem_to_oqs_name(kem_arg, oqs_name, sizeof(oqs_name));

    if (header)
        printf("role%cpattern%ckem%clabel%criter%clatency_ms%crc\n", sep,sep,sep,sep,sep,sep);

    const int rc = role_char_initiator(pattern); // Determine whether the local end should have a static key (K/I)
    const int have_static = (rc=='K' || rc=='I') && client_priv_pq && client_pub_pq;

    for(int i=0;i<iters;i++){
        int sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd<0) return 1;
        if (connect(sd, (struct sockaddr*)&(struct sockaddr_in){
                .sin_family=AF_INET, .sin_port=htons((uint16_t)port),
            }, sizeof(struct sockaddr_in)) < 0) {
            // The above used a temporary literal; it needs to be rewritten to support the host:
            struct sockaddr_in srv; memset(&srv,0,sizeof(srv));
            srv.sin_family = AF_INET; srv.sin_port = htons((uint16_t)port);
            if (inet_pton(AF_INET, host, &srv.sin_addr)!=1){ close(sd); return 1; }
            if (connect(sd, (struct sockaddr*)&srv, sizeof(srv))<0){ close(sd); return 1; }
        }
        int one = 1; setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        NoiseHandshakeState *hs=NULL;
        int err = noise_handshakestate_new_by_name(&hs, proto_name, NOISE_ROLE_INITIATOR);
        if (getenv("PQ_WHITEBOX")) fprintf(stderr, "[PQWB] proto=%s err=%d\n", proto_name, err);
        if (err!=NOISE_ERROR_NONE){ close(sd); return 1; }

        // Before the handshake begins: Provide all the necessary local keys.
        while (noise_handshakestate_needs_local_keypair(hs)) {
            err = supply_local_keypair(hs, have_static, client_priv_pq, client_priv_pq_len,
                                              client_pub_pq,  client_pub_pq_len, oqs_name);
            if (err!=NOISE_ERROR_NONE) break;
        }
        if (err!=NOISE_ERROR_NONE){ noise_handshakestate_free(hs); close(sd); return 1; }

        // Provide the remote static public key when needed (it will be replenished in a loop later).
        if (noise_handshakestate_needs_remote_public_key(hs) && server_pub_pq && server_pub_pq_len){
            NoiseDHState *rdh = noise_handshakestate_get_remote_public_key_dh(hs);
            err = noise_dhstate_set_public_key(rdh, server_pub_pq, server_pub_pq_len);
            if (err!=NOISE_ERROR_NONE){ noise_handshakestate_free(hs); close(sd); return 1; }
        }

        int ok = 1, action;
        NoiseBuffer nb;
        struct timespec t0,t1;
        clock_gettime(CLOCK_MONOTONIC,&t0);

        err = noise_handshakestate_start(hs);
        if (err!=NOISE_ERROR_NONE) ok=0;

        while (ok) {
            action = noise_handshakestate_get_action(hs);
            if (action == NOISE_ACTION_WRITE_MESSAGE) {
                noise_buffer_set_output(nb, message+2, sizeof(message)-2);
                err = noise_handshakestate_write_message(hs, &nb, NULL);
                if (err!=NOISE_ERROR_NONE){ ok=0; break; }
                const size_t sz = nb.size;
                message[0]=(uint8_t)(sz>>8); message[1]=(uint8_t)sz;
                size_t sent=0, total=sz+2;
                while (sent < total) {
                    size_t chunk = (total-sent)<1448 ? (total-sent) : 1448;
                    ssize_t w = send(sd, message+sent, chunk, 0);
                    if (w<=0){ ok=0; break; }
                    sent += (size_t)w;
                }
                if (!ok) break;

                // After writing a message: If the local/remote public key is needed again, supply it in a loop.
                while (noise_handshakestate_needs_local_keypair(hs)) {
                    int err2 = supply_local_keypair(hs, have_static, client_priv_pq, client_priv_pq_len,
                                                          client_pub_pq,  client_pub_pq_len, oqs_name);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                }
                if (!ok) break;
                if (noise_handshakestate_needs_remote_public_key(hs) && server_pub_pq && server_pub_pq_len){
                    NoiseDHState *rdh = noise_handshakestate_get_remote_public_key_dh(hs);
                    int err2 = noise_dhstate_set_public_key(rdh, server_pub_pq, server_pub_pq_len);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                }

            } else if (action == NOISE_ACTION_READ_MESSAGE) {
                size_t need=2, got=0;
                while (got<need) {
                    ssize_t r = recv(sd, message+got, need-got, 0);
                    if (r<=0){ ok=0; break; }
                    got += (size_t)r;
                    if (need==2 && got==2) { need = ((size_t)message[0]<<8) + message[1] + 2; }
                }
                if (!ok) break;
                noise_buffer_set_input(nb, message+2, need-2);
                err = noise_handshakestate_read_message(hs, &nb, NULL);
                if (err!=NOISE_ERROR_NONE){ ok=0; break; }

                // After reading a message: If the local/remote public key is needed again, supply it in a loop.
                while (noise_handshakestate_needs_local_keypair(hs)) {
                    int err2 = supply_local_keypair(hs, have_static, client_priv_pq, client_priv_pq_len,
                                                          client_pub_pq,  client_pub_pq_len, oqs_name);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                }
                if (!ok) break;
                if (noise_handshakestate_needs_remote_public_key(hs) && server_pub_pq && server_pub_pq_len){
                    NoiseDHState *rdh = noise_handshakestate_get_remote_public_key_dh(hs);
                    int err2 = noise_dhstate_set_public_key(rdh, server_pub_pq, server_pub_pq_len);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                }

            } else if (action == NOISE_ACTION_SPLIT) {
                NoiseCipherState *sc=NULL, *rc=NULL;
                err = noise_handshakestate_split(hs, &sc, &rc);
                if (sc) noise_cipherstate_free(sc);
                if (rc) noise_cipherstate_free(rc);
                break;
            } else if (action == NOISE_ACTION_NONE) {
                int progressed = 0;
                while (noise_handshakestate_needs_local_keypair(hs)) {
                    int err2 = supply_local_keypair(hs, have_static, client_priv_pq, client_priv_pq_len,
                                                          client_pub_pq,  client_pub_pq_len, oqs_name);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                    progressed = 1;
                }
                if (!ok) break;
                if (noise_handshakestate_needs_remote_public_key(hs) && server_pub_pq && server_pub_pq_len){
                    NoiseDHState *rdh = noise_handshakestate_get_remote_public_key_dh(hs);
                    int err2 = noise_dhstate_set_public_key(rdh, server_pub_pq, server_pub_pq_len);
                    if (err2!=NOISE_ERROR_NONE){ ok=0; break; }
                    progressed = 1;
                }
                if (progressed) continue;
            } else {
                break;
            }
        }

        clock_gettime(CLOCK_MONOTONIC,&t1);
        double ms = diff_ms(&t0,&t1);
        if (i>=warmup)
            printf("client%c%s%c%s%c%s%c%d%c%.3f%c%d\n",
                   sep, pattern, sep, kem_tok, sep, label, sep, i, sep, ms, sep, ok?0:1);

        noise_handshakestate_free(hs);
        close(sd);
    }

    free(server_pub_pq);
    free(client_priv_pq); free(client_pub_pq);
    return 0;
}
