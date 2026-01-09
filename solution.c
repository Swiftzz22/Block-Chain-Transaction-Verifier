#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <unistd.h>

// ==== ROADMAP ====
// 1) Read test_case id, open input + transaction files
// 2) Build adjacency listzzzz from transactions (wallet → txns)
// 3) Attach shared memory + message queue
// 4) For each block → recv helper msg → decrypt wallets → sum valid txn
// 5) Reply to helper, cleanupzzzz (good practice!!)

// Const sizes
#define WALLET_HASH_SIZE 16
#define MAX_WALLETS_PER_BLOCK 100
#define SANIA_HASHMAP_SIZE 1024 // must be power of 2 for mask magic

// ==== MSG BUFFERS ====
struct RecvMessageBuffer {
	long mtype;
	int security_value;
	int decryption_key;
};

struct SendMessageBuffer {
	long mtype;
	long sum;
};

// ==== BLOCK + TXN ====
struct Block {
	int wallet_count;
	char wallet_hashes[MAX_WALLETS_PER_BLOCK][WALLET_HASH_SIZE + 1];
};

struct Transaction {
	long timestamp;
	char tx_hash[64];
	char sender[WALLET_HASH_SIZE + 1];
	char receiver[WALLET_HASH_SIZE + 1];
	long long amount;
	int leading_zeroes;
};

struct WalletNode {
	char wallet_id[WALLET_HASH_SIZE + 1];
	int count;
	struct WalletNode* next_node;
};

struct WalletAdj { int tx_index; };

struct WalletAdjList {
	char wallet_id[WALLET_HASH_SIZE + 1];
	int size;
	int capacity;
	struct WalletAdj* entries;
	struct WalletAdjList* next_node;
};

// global adjacency mapzzzz
static struct WalletAdjList* global_wallet_adj_map_sk[SANIA_HASHMAP_SIZE];

// ==== HASH FUNC (djb2 like) ====
static unsigned int compute_hash_sk(const char* wallet_str) {
	unsigned int h = 5381U;
	for (int i = 0; i < WALLET_HASH_SIZE; i++) {
		h = ((h << 5) + h) + (unsigned char)wallet_str[i];
	}
	return h & (SANIA_HASHMAP_SIZE - 1);
}

// ==== DECRYPT WALLET ====
static void decrypt_wallet_sk(const char *encrypted, char *decrypted, int key) {
	int len = WALLET_HASH_SIZE;
	key %= len;
	if (key == 0) {
		strcpy(decrypted, encrypted);
		return;
	}
	for (int i = 0; i < len; i++) {
		decrypted[i] = encrypted[(i - key + len) % len];
	}
	decrypted[len] = '\0';
}

// ==== COUNT LEADING ZEROES ====
static int count_sk_leading_zeros(const char *string) {
	int count = 0;
	while (string[count]!='\0'&&string[count] == '0') count++;
	return count;
}

// ==== HASHMAP HELPERS ====
static int wallet_exists_sk(struct WalletNode** hashmap, const char* wallet) {
	unsigned int b = compute_hash_sk(wallet);
	struct WalletNode* cur = hashmap[b];
	while (cur) {
		if (memcmp(cur->wallet_id, wallet, WALLET_HASH_SIZE) == 0) return cur->count;
		cur = cur->next_node;
	}
	return 0;
}

static void wallet_insert_sk(struct WalletNode** hashmap, const char* wallet) {
	unsigned int b = compute_hash_sk(wallet);
	struct WalletNode* cur = hashmap[b];
	while (cur) {
		if (memcmp(cur->wallet_id, wallet, WALLET_HASH_SIZE) == 0) {
			cur->count++;
			return;
		}
		cur = cur->next_node;
	}
	struct WalletNode* node = malloc(sizeof(struct WalletNode));
	memcpy(node->wallet_id, wallet, WALLET_HASH_SIZE);
	node->wallet_id[WALLET_HASH_SIZE] = '\0';
	node->count = 1;
	node->next_node = hashmap[b];
	hashmap[b] = node;
}

static void hashmap_cleanup_sk(struct WalletNode** hashmap) {
	for (int i = 0; i < SANIA_HASHMAP_SIZE; i++) {
		struct WalletNode* cur = hashmap[i];
		while (cur) {
			struct WalletNode* tmp = cur;
			cur = cur->next_node;
			free(tmp);
		}
		hashmap[i] = NULL;
	}
	// Clean up hashmap memory - good practice!!
}

// ==== ADJ LIST HELPERS ====
static void ensure_adj_capacity_sk(struct WalletAdjList* lst) {
	if (lst->size < lst->capacity) return;
	int newcap = lst->capacity == 0 ? 4 : lst->capacity * 2;
	struct WalletAdj* n = realloc(lst->entries, sizeof(struct WalletAdj) * newcap);
	if (!n) exit(1);
	lst->entries = n;
	lst->capacity = newcap;
}

static struct WalletAdjList* get_or_create_adjlist_sk(const char* wallet) {
	unsigned int b = compute_hash_sk(wallet);
	struct WalletAdjList* cur = global_wallet_adj_map_sk[b];
	while (cur) {
		if (memcmp(cur->wallet_id, wallet, WALLET_HASH_SIZE) == 0) return cur;
		cur = cur->next_node;
	}
	struct WalletAdjList* node = calloc(1, sizeof(struct WalletAdjList));
	memcpy(node->wallet_id, wallet, WALLET_HASH_SIZE);
	node->wallet_id[WALLET_HASH_SIZE] = '\0';
	node->entries = NULL;
	node->size = node->capacity = 0;
	node->next_node = global_wallet_adj_map_sk[b];
	global_wallet_adj_map_sk[b] = node;
	return node;
}

// ==== LOAD TRANSACTIONS ====
static struct Transaction* load_transactions_sk(const char *file, int *num_loaded) {
	FILE *fp = fopen(file, "r"); // open txn
	if (!fp) exit(1);
	int cap = 10000, count = 0;
	struct Transaction *txns = malloc(sizeof(struct Transaction) * cap);
	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		if (count >= cap) {
			cap *= 2;
			txns = realloc(txns, sizeof(struct Transaction) * cap);
		}
		struct Transaction *tx = &txns[count];
		if (sscanf(line, "%ld %s %s %s %lld", &tx->timestamp, tx->tx_hash, tx->sender, tx->receiver, &tx->amount) != 5)
			continue;
		tx->leading_zeroes = count_sk_leading_zeros(tx->tx_hash);

		// add sender adj
		struct WalletAdjList* snd = get_or_create_adjlist_sk(tx->sender);
		ensure_adj_capacity_sk(snd);
		snd->entries[snd->size++].tx_index = count;

		// add receiver adj (if not same as sender)
		if (strcmp(tx->sender, tx->receiver) != 0) {
			struct WalletAdjList* rcv = get_or_create_adjlist_sk(tx->receiver);
			ensure_adj_capacity_sk(rcv);
			rcv->entries[rcv->size++].tx_index = count;
		}
		count++;
	}
	fclose(fp);
	*num_loaded = count;
	return txns;
}

// ==== PROCESS BLOCK ====
static long long process_block_sk(struct Block *block, int security, int dkey, 
								  struct Transaction *txns, int n) {
	long long total = 0;
	struct WalletNode* wallet_map_sk[SANIA_HASHMAP_SIZE] = {0};

	// decrypt + insert wallets
	for (int i = 0; i < MAX_WALLETS_PER_BLOCK; i++) {
		if (strlen(block->wallet_hashes[i]) == WALLET_HASH_SIZE) {
			char w[WALLET_HASH_SIZE + 1];
			decrypt_wallet_sk(block->wallet_hashes[i], w, dkey);
			wallet_insert_sk(wallet_map_sk, w);
		} else if (block->wallet_hashes[i][0] == '\0') break;
	}

	// candidate txn markzzzz
	unsigned char *marked = calloc(n, 1);
	int cap = 256, used = 0;
	int *idxs = malloc(sizeof(int) * cap);

	for (int i = 0; i < MAX_WALLETS_PER_BLOCK; i++) {
		if (strlen(block->wallet_hashes[i]) != WALLET_HASH_SIZE) {
			if (block->wallet_hashes[i][0] == '\0') break;
			continue;
		}
		char w[WALLET_HASH_SIZE + 1];
		decrypt_wallet_sk(block->wallet_hashes[i], w, dkey);
		if (!wallet_exists_sk(wallet_map_sk, w)) continue;

		unsigned int b = compute_hash_sk(w);
		struct WalletAdjList* lst = global_wallet_adj_map_sk[b];
		while (lst && memcmp(lst->wallet_id, w, WALLET_HASH_SIZE) != 0) lst = lst->next_node;
		if (!lst) continue;

		for (int j = 0; j < lst->size; j++) {
			int ti = lst->entries[j].tx_index;
			if (!marked[ti]) {
				marked[ti] = 1;
				if (used == cap) {
					cap <<= 1;
					idxs = realloc(idxs, sizeof(int) * cap);
				}
				idxs[used++] = ti;
			}
		}
	}

	// compute sumzzzz
	for (int k = 0; k < used; k++) {
		struct Transaction *tx = &txns[idxs[k]];
		if (tx->leading_zeroes < security) continue;
		int sc = wallet_exists_sk(wallet_map_sk, tx->sender);
		int rc = wallet_exists_sk(wallet_map_sk, tx->receiver);

		if (sc && rc) {
			if (strcmp(tx->sender, tx->receiver) == 0)
				total += (long long)tx->amount * sc;
			else
				total += (long long)tx->amount * (sc + rc);
		} else if (sc || rc) {
			total += (long long)tx->amount * (sc ? sc : rc);
		}
	}

	free(marked);
	free(idxs);
	hashmap_cleanup_sk(wallet_map_sk);
	return total;
}

int main(int argc, char *argv[]) {
	if (argc != 2) exit(1);
	int t = atoi(argv[1]);

	char input_file[64], txn_file[64];
	sprintf(input_file, "input_%d.txt", t);
	sprintf(txn_file, "transactions_%d.txt", t);

	FILE *fp = fopen(input_file, "r");
	if (!fp) exit(1);
	int total_tx, num_blocks;
	key_t shm_key, msg_key;
	fscanf(fp, "%d", &total_tx);
	fscanf(fp, "%d", &num_blocks);
	fscanf(fp, "%d", &shm_key);
	fscanf(fp, "%d", &msg_key);
	fclose(fp); // close when no use 

	int n_tx;
	struct Transaction *txns = load_transactions_sk(txn_file, &n_tx);

	int shm_id = shmget(shm_key, sizeof(struct Block) * num_blocks, 0666);
	if (shm_id == -1) exit(1);
	struct Block *shm_ptr = (struct Block *)shmat(shm_id, NULL, 0);
	if (shm_ptr == (void *)-1) exit(1);

	int msg_id = msgget(msg_key, 0666);
	if (msg_id == -1) exit(1);

	// loop over blockzzzz
	for (int i = 0; i < num_blocks; i++) {
		struct RecvMessageBuffer in_msg;
		struct SendMessageBuffer out_msg;

		if (msgrcv(msg_id, &in_msg, sizeof(in_msg) - sizeof(long), 2, 0) == -1) break;
		if (in_msg.security_value == -1 && in_msg.decryption_key == -1) break;

		long long sum = process_block_sk(&shm_ptr[i],
										 in_msg.security_value,
										 in_msg.decryption_key,
										 txns, n_tx);
		out_msg.mtype = 1;
		out_msg.sum = sum;
		if (msgsnd(msg_id, &out_msg, sizeof(out_msg) - sizeof(long), 0) == -1) exit(1);
	}

	// detach + cleanup
	shmdt(shm_ptr);
	free(txns);

	for (int i = 0; i < SANIA_HASHMAP_SIZE; i++) {
		struct WalletAdjList* cur = global_wallet_adj_map_sk[i];
		while (cur) {
			struct WalletAdjList* tmp = cur;
			cur = cur->next_node;
			free(tmp->entries);
			free(tmp);
		}
		global_wallet_adj_map_sk[i] = NULL;
	}
	return 0;
}
