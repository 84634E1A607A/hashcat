/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "thread.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "parser.h"
#include "emu_inc_cipher_des.h"
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "NetNTLMv1 / NetNTLMv1+ESS";
static const u64   KERN_TYPE      = 5500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_MULTI_SALT_FUSED
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14
                                  | OPTS_TYPE_PT_UTF16LE
                                  | OPTS_TYPE_AMP_TAIL
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920";

typedef struct netntlm
{
  int user_len;
  int domain_len;
  int srvchall_len;
  int clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static void transform_netntlmv1_key (const u8 *nthash, u8 *key)
{
  key[0] =                    (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}

// Tail-key schedules depend only on the suffix. Reuse them across records.

#define NN_TAIL_SCHED_ENTRIES 0x10000
#define NN_TAIL_SCHED_WORDS   32

static u32 *nn_tail_sched = NULL;

// Serialize shared schedule initialization and scan publishers across contexts.

static hc_thread_mutex_t nn_tail_lock;

static void __attribute__ ((constructor)) nn_tail16_init (void)
{
  hc_thread_mutex_init (nn_tail_lock);
}

static void nn_tail_sched_build (void)
{
  if (nn_tail_sched != NULL) return;

  u32 *sched = (u32 *) hcmalloc ((size_t) NN_TAIL_SCHED_ENTRIES * NN_TAIL_SCHED_WORDS * sizeof (u32));

  for (u32 i = 0; i < NN_TAIL_SCHED_ENTRIES; i++)
  {
    u32 key_md4[2] = { 0 };
    u32 key_des[2] = { 0 };

    key_md4[0] = i;

    transform_netntlmv1_key ((const u8 *) key_md4, (u8 *) key_des);

    u32 *Kc = &sched[(size_t) i * NN_TAIL_SCHED_WORDS];
    u32 *Kd = &Kc[16];

    _des_crypt_keysetup (key_des[0], key_des[1], Kc, Kd, (u32 (*)[64]) c_skb);
  }

  nn_tail_sched = sched;
}

// Workers scan disjoint suffix ranges and atomically lower the best match.
// Return the lowest matching suffix, preserving the serial scan's result.
// A worker can stop once its cursor reaches the shared best suffix.

#define NN_TAIL16_SCAN_THREADS_MAX 32

typedef struct nn_tail16_job
{
  u32 lo;
  u32 hi;
  const u32 *sched;
  u32 block[2];
  u32 want[2];
  u64 *best;

  u64 mine;

} nn_tail16_job_t;

// Reuse worker threads across records to avoid per-record create/join overhead.

typedef struct nn_tail16_pool
{
  u32 threads;
  u32 started;

  hc_thread_t tid[NN_TAIL16_SCAN_THREADS_MAX];

  hc_thread_mutex_t lock;
  hc_thread_cond_t  go;
  hc_thread_cond_t  done_cond;
  hc_thread_cond_t  parked_cond;

  u32 gen;
  u32 parked;
  u32 finished;
  bool stop;

  nn_tail16_job_t job[NN_TAIL16_SCAN_THREADS_MAX];
  u64 best;

} nn_tail16_pool_t;

static nn_tail16_pool_t *nn_tail16_pool = NULL;

static u32 nn_tail16_scan_threads_env (void)
{
  i32 n = NN_TAIL16_SCAN_THREADS_MAX;

  const char *env = getenv ("NN_TAIL16_SCAN_THREADS");

  if (env != NULL) n = atoi (env);

  if (n > NN_TAIL16_SCAN_THREADS_MAX) n = NN_TAIL16_SCAN_THREADS_MAX;
  if (n < 0)                            n = 0;

  return n;
}

// Stop higher slices early when another worker finds a lower matching suffix.

static void nn_tail16_scan_slice (nn_tail16_job_t *job)
{
  job->mine = (u64) -1;

  for (u32 i = job->lo; i < job->hi; i++)
  {
    if (((i - job->lo) & 0x3f) == 0)
    {
      const u64 seen = __atomic_load_n (job->best, __ATOMIC_RELAXED);

      if (seen <= (u64) i) return;
    }

    u32 Kc[16] = { 0 };
    u32 Kd[16] = { 0 };

    const u32 *s = &job->sched[(size_t) i * NN_TAIL_SCHED_WORDS];

    for (u32 k = 0; k < 16; k++)
    {
      Kc[k] = s[k +  0];
      Kd[k] = s[k + 16];
    }

    u32 data3[2] = { job->block[0], job->block[1] };

    _des_crypt_encrypt (data3, data3, Kc, Kd, (u32 (*)[64]) c_SPtrans);

    if (data3[0] != job->want[0]) continue;
    if (data3[1] != job->want[1]) continue;

    job->mine = i;

    u64 cur = __atomic_load_n (job->best, __ATOMIC_RELAXED);

    while ((u64) i < cur)
    {
      if (__atomic_compare_exchange_n (job->best, &cur, (u64) i, 1, __ATOMIC_RELAXED, __ATOMIC_RELAXED) == 1) break;
    }

    return;
  }
}

typedef struct nn_tail16_worker
{
  nn_tail16_pool_t *pool;
  u32 idx;

} nn_tail16_worker_t;

static nn_tail16_worker_t nn_tail16_workers[NN_TAIL16_SCAN_THREADS_MAX];

static HC_THREAD_FUNC nn_tail16_worker (void *p)
{
  nn_tail16_worker_t *self = (nn_tail16_worker_t *) p;
  nn_tail16_pool_t   *pool = self->pool;

  for (;;)
  {
    hc_thread_mutex_lock (pool->lock);

    const u32 mygen = pool->gen;

    pool->parked++;

    hc_thread_cond_signal (pool->parked_cond);

    while ((pool->gen == mygen) && (pool->stop == false))
    {
      hc_thread_cond_wait (pool->go, pool->lock);
    }

    if (pool->stop == true)
    {
      pool->parked--;

      hc_thread_mutex_unlock (pool->lock);

      return 0;
    }

    pool->parked--;

    hc_thread_mutex_unlock (pool->lock);

    nn_tail16_scan_slice (&pool->job[self->idx]);

    hc_thread_mutex_lock (pool->lock);

    pool->finished++;

    hc_thread_cond_signal (pool->done_cond);

    hc_thread_mutex_unlock (pool->lock);
  }

  return 0;
}

// The caller holds nn_tail_lock until every worker reports its result.

static u64 nn_tail16_pool_run (nn_tail16_pool_t *pool, const u32 *sched, const u32 block0, const u32 block1, const u32 want0, const u32 want1)
{
  hc_thread_mutex_lock (pool->lock);

  while (pool->parked < pool->threads)
  {
    hc_thread_cond_wait (pool->parked_cond, pool->lock);
  }

  u64 best = (u64) -1;

  const u32 chunk = (0x10000 + pool->threads - 1) / pool->threads;

  for (u32 k = 0; k < pool->threads; k++)
  {
    const u32 lo = (u32) k * chunk;

    u32 hi = lo + chunk;

    if (hi > 0x10000) hi = 0x10000;

    pool->job[k].lo       = lo;
    pool->job[k].hi       = hi;
    pool->job[k].sched    = sched;
    pool->job[k].block[0] = block0;
    pool->job[k].block[1] = block1;
    pool->job[k].want[0]  = want0;
    pool->job[k].want[1]  = want1;
    pool->job[k].best     = &pool->best;
    pool->job[k].mine     = (u64) -1;
  }

  pool->best     = (u64) -1;
  pool->finished = 0;
  pool->gen++;

  hc_thread_cond_broadcast (pool->go);

  while (pool->finished < pool->threads)
  {
    hc_thread_cond_wait (pool->done_cond, pool->lock);
  }

  best = pool->best;

  hc_thread_mutex_unlock (pool->lock);

  return best;
}

static nn_tail16_pool_t *nn_tail16_pool_get (void)
{
  static bool nn_tried = false;

  if (nn_tried == true) return nn_tail16_pool;

  nn_tried = true;

  const u32 threads = nn_tail16_scan_threads_env ();

  if (threads <= 1) return NULL;

  nn_tail16_pool_t *pool = (nn_tail16_pool_t *) hcmalloc (sizeof (nn_tail16_pool_t));

  memset (pool, 0, sizeof (nn_tail16_pool_t));

  pool->threads = threads;

  hc_thread_mutex_init (pool->lock);
  hc_thread_cond_init  (pool->go);
  hc_thread_cond_init  (pool->done_cond);
  hc_thread_cond_init  (pool->parked_cond);

  for (u32 k = 0; k < threads; k++)
  {
    nn_tail16_workers[k].pool = pool;
    nn_tail16_workers[k].idx  = k;

    hc_thread_t tid;

    if (hc_thread_create_ok (tid, nn_tail16_worker, &nn_tail16_workers[k]) == 0)
    {
      // Partition future scans among the workers that actually started.

      pool->threads = k;

      break;
    }

    pool->tid[k] = tid;
    pool->started = k + 1;
  }

  if (pool->threads <= 1)
  {
    // The caller scans serially when fewer than two workers started.

    pool->threads = 1;
  }

  nn_tail16_pool = pool;

  return pool;
}

// Join workers before dlclose unmaps the module code they are waiting in.

static void nn_tail16_pool_shutdown (void)
{
  nn_tail16_pool_t *pool = nn_tail16_pool;

  if (pool == NULL) return;

  hc_thread_mutex_lock (pool->lock);

  pool->stop = true;

  pool->gen++;

  hc_thread_cond_broadcast (pool->go);

  hc_thread_mutex_unlock (pool->lock);

  for (u32 k = 0; k < pool->started; k++)
  {
    hc_thread_join (pool->tid[k]);
  }

  hc_thread_cond_delete (pool->parked_cond);
  hc_thread_cond_delete (pool->done_cond);
  hc_thread_cond_delete (pool->go);
  hc_thread_mutex_delete (pool->lock);

  hcfree (pool);

  nn_tail16_pool = NULL;
}

static void __attribute__ ((destructor)) nn_tail16_pool_fini (void)
{
  nn_tail16_pool_shutdown ();

  hcfree (nn_tail_sched);

  nn_tail_sched = NULL;

  hc_thread_mutex_delete (nn_tail_lock);
}

// Preserve the serial scan's lowest matching suffix, or return (u64) -1.

static u64 nn_tail16_scan (const u32 *sched, const u32 block0, const u32 block1, const u32 want0, const u32 want1)
{
  hc_thread_mutex_lock (nn_tail_lock);

  nn_tail16_pool_t *pool = nn_tail16_pool_get ();

  if ((pool == NULL) || (pool->threads <= 1))
  {
    u64 best = (u64) -1;

    nn_tail16_job_t job;

    job.lo       = 0;
    job.hi       = 0x10000;
    job.sched    = sched;
    job.block[0] = block0;
    job.block[1] = block1;
    job.want[0]  = want0;
    job.want[1]  = want1;
    job.best     = &best;

    nn_tail16_scan_slice (&job);

    hc_thread_mutex_unlock (nn_tail_lock);

    return job.mine;
  }

  const u64 best = nn_tail16_pool_run (pool, sched, block0, block1, want0, want1);

  hc_thread_mutex_unlock (nn_tail_lock);

  return best;
}

char *module_jit_build_options(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // The single-digest CUDA mask kernel rarely reaches DES. Constant tables
  // avoid shared-table initialization and its block barrier.

  const bool mask_kernel = ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0) && (user_options->attack_mode == ATTACK_MODE_BF) && (hashes->digests_cnt == 1) && (device_param->is_cuda == true);

  // Keep this predicate equal to run_cracker_salt_major. Pure kernels have
  // OPTS_TYPE_MULTI_SALT_FUSED cleared by interface.c.
  // Generic host generators also use the straight kernel. Association uses
  // the same kernel but pairs each candidate with one salt, so exclude it.
  // CUDA stages 4096 sessions on sm_80 and later, or 512 on older devices.
  // OpenCL and HIP use 1536 without a queue: 28 KiB leaves 4 KiB spare on
  // devices with 32 KiB local memory. Larger inputs use multiple windows.
  // TODO: Above 32 KiB, derive window candidates from runtime local-memory
  // capacity and autotune them online instead of using the fixed limit.

  char fuse_str[192] = "";

  const bool fuse_attack = ((user_options_extra->attack_kern == ATTACK_KERN_BF) || (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)) && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION);
  const bool fuse_device = ((device_param->is_cuda == true) && (device_param->sm_major >= 5)) || (device_param->is_opencl == true) || (device_param->is_hip == true);
  const bool fuse_salts = ((hashconfig->opts_type & OPTS_TYPE_MULTI_SALT_FUSED) != 0) && (fuse_attack == true) && (hashes->salts_cnt > 1) && (device_param->vector_width == 1) && (fuse_device == true);

  // Fused kernels require REAL_SHM. FORCE_DISABLE_SHM only applies to
  // single-digest mask runs, so it cannot overlap with fusion.

  if (fuse_salts == true)
  {
    const u32 nn_cuda_max = (device_param->sm_major >= 8) ? 4096 : 512;
    const u32 nn_max = (device_param->is_cuda == true) ? nn_cuda_max : 1536;
    const u32 nn_win = (hashes->salts_cnt < nn_max) ? (const u32) hashes->salts_cnt : nn_max;

    snprintf (fuse_str, sizeof (fuse_str), " -D NN_FUSE_SALTS=%u -D NN_FUSE_TOTAL_MAX=%u -D NN_FUSE_CAP=%u", nn_win, (const u32) hashes->salts_cnt, (const u32) hashes->digests_cnt);

    // CUDA straight kernels use a survivor queue at 256 salts and above.
    // Keep other backends on the direct walk to stay within the 28 KiB budget.
    // The mask kernel ignores this define.
    if ((device_param->is_cuda == true) && (hashes->salts_cnt >= 256))
    {
      strncat (fuse_str, " -D NN_FUSE_DENSEQ", sizeof (fuse_str) - strlen (fuse_str) - 1);
    }
  }

  // Intel CPU
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU))
  {
    hc_asprintf (&jit_build_options, mask_kernel ? "-D _unroll -D FORCE_DISABLE_SHM%s" : "-D _unroll%s", fuse_str);
  }
  else if (mask_kernel == true)
  {
    hc_asprintf (&jit_build_options, "-D FORCE_DISABLE_SHM%s", fuse_str);
  }
  else if (fuse_str[0] != 0)
  {
    hc_asprintf (&jit_build_options, "%s", fuse_str + 1);
  }

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (netntlm_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  netntlm_t *netntlm = (netntlm_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  // username
  token.sep[0]     = ':';
  token.len_min[0] = 0;
  token.len_max[0] = 60;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  // unused
  token.sep[1]     = ':';
  token.len[1]     = 0;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  // domain
  token.sep[2]     = ':';
  token.len_min[2] = 0;
  token.len_max[2] = 45;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // lm response
  token.sep[3]     = ':';
  token.len_min[3] = 0;
  token.len_max[3] = 48;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // ntlm response
  token.sep[4]     = ':';
  token.len[4]     = 48;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // challenge
  token.sep[5]     = ':';
  token.len[5]     = 16;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos     = token.buf[0];
  const u8 *domain_pos   = token.buf[2];
  const u8 *srvchall_pos = token.buf[3];
  const u8 *hash_pos     = token.buf[4];
  const u8 *clichall_pos = token.buf[5];

  const int user_len     = token.len[0];
  const int domain_len   = token.len[2];
  const int srvchall_len = token.len[3];
  const int clichall_len = token.len[5];

  /**
   * store some data for later use
   */

  netntlm->user_len     = user_len     * 2;
  netntlm->domain_len   = domain_len   * 2;
  netntlm->srvchall_len = srvchall_len / 2;
  netntlm->clichall_len = clichall_len / 2;

  u8 *userdomain_ptr = (u8 *) netntlm->userdomain_buf;
  u8 *chall_ptr      = (u8 *) netntlm->chall_buf;

  /**
   * handle username and domainname
   */

  for (int i = 0; i < user_len; i++)
  {
    *userdomain_ptr++ = user_pos[i];
    *userdomain_ptr++ = 0;
  }

  for (int i = 0; i < domain_len; i++)
  {
    *userdomain_ptr++ = domain_pos[i];
    *userdomain_ptr++ = 0;
  }

  /**
   * handle server challenge encoding
   */

  if (srvchall_len & 1) return (PARSER_TOKEN_LENGTH);

  // i + 1, not i: the loop reads two characters per byte, so an odd srvchall_len read one past the
  // token, which is the next field of the line or the caller's terminator

  for (int i = 0; (i + 1) < srvchall_len; i += 2)
  {
    const u8 p0 = srvchall_pos[i + 0];
    const u8 p1 = srvchall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * handle client challenge encoding
   */

  if (clichall_len & 1) return (PARSER_TOKEN_LENGTH);

  // i + 1, not i: the loop reads two characters per byte, so an odd clichall_len read one past the
  // token, which is the next field of the line or the caller's terminator

  for (int i = 0; (i + 1) < clichall_len; i += 2)
  {
    const u8 p0 = clichall_pos[i + 0];
    const u8 p1 = clichall_pos[i + 1];

    *chall_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  /**
   * store data
   */

  const bool parse_rc = generic_salt_decode (hashconfig, clichall_pos, clichall_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  /* special case, last 8 byte do not need to be checked since they are brute-forced next */

  u32 digest_tmp[2];

  digest_tmp[0] = hex_to_u32 (hash_pos + 32);
  digest_tmp[1] = hex_to_u32 (hash_pos + 40);

  /* special case 2: ESS */

  if (srvchall_len == 48)
  {
    if ((netntlm->chall_buf[2] == 0) && (netntlm->chall_buf[3] == 0) && (netntlm->chall_buf[4] == 0) && (netntlm->chall_buf[5] == 0))
    {
      u32 w[16] = { 0 };

      w[ 0] = salt->salt_buf[0];
      w[ 1] = salt->salt_buf[1];
      w[ 2] = netntlm->chall_buf[0];
      w[ 3] = netntlm->chall_buf[1];
      w[ 4] = 0x80;
      w[14] = 16 * 8;

      u32 dgst[4] = { 0 };

      dgst[0] = MD5M_A;
      dgst[1] = MD5M_B;
      dgst[2] = MD5M_C;
      dgst[3] = MD5M_D;

      md5_transform (w + 0, w + 4, w + 8, w + 12, dgst);

      salt->salt_buf[0] = dgst[0];
      salt->salt_buf[1] = dgst[1];
    }
  }

  /* precompute netntlmv1 exploit start */

  const u32 *nn_sched = nn_tail_sched;

  const u64 nn_tail16 = nn_tail16_scan (nn_sched, salt->salt_buf[0], salt->salt_buf[1], digest_tmp[0], digest_tmp[1]);

  // No recovered tail key means the response does not fit the effective challenge.

  if (nn_tail16 == (u64) -1) return (PARSER_SALT_VALUE);

  salt->salt_buf[2] = (u32) nn_tail16;

  salt->salt_len = 24;

  salt->salt_buf_pc[0] = digest_tmp[0];
  salt->salt_buf_pc[1] = digest_tmp[1];

  /* precompute netntlmv1 exploit stop */

  DES_IP (digest[0], digest[1]);
  DES_IP (digest[2], digest[3]);

  digest[0] = rotr32 (digest[0], 29);
  digest[1] = rotr32 (digest[1], 29);
  digest[2] = rotr32 (digest[2], 29);
  digest[3] = rotr32 (digest[3], 29);

  DES_IP (salt->salt_buf[0], salt->salt_buf[1]);

  salt->salt_buf[0] = rotl32 (salt->salt_buf[0], 3);
  salt->salt_buf[1] = rotl32 (salt->salt_buf[1], 3);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const netntlm_t *netntlm = (const netntlm_t *) esalt_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[4];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];

  tmp[0] = rotl32 (tmp[0], 29);
  tmp[1] = rotl32 (tmp[1], 29);
  tmp[2] = rotl32 (tmp[2], 29);
  tmp[3] = rotl32 (tmp[3], 29);

  DES_FP (tmp[1], tmp[0]);
  DES_FP (tmp[3], tmp[2]);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  const u8 *ptr = (const u8 *) netntlm->userdomain_buf;

  for (int i = 0; i < netntlm->user_len; i += 2)
  {
    out_buf[out_len++] = ptr[i];
  }

  out_buf[out_len++] = ':';
  out_buf[out_len++] = ':';

  ptr += netntlm->user_len;

  for (int i = 0; i < netntlm->domain_len; i += 2)
  {
    out_buf[out_len++] = ptr[i];
  }

  out_buf[out_len++] = ':';

  ptr = (const u8 *) netntlm->chall_buf;

  for (int i = 0; i < netntlm->srvchall_len; i++)
  {
    u8_to_hex (ptr[i], out_buf + out_len); out_len += 2;
  }

  out_buf[out_len++] = ':';

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;

  u32_to_hex (salt->salt_buf_pc[0], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf_pc[1], out_buf + out_len); out_len += 8;

  out_buf[out_len++] = ':';

  ptr += netntlm->srvchall_len;

  for (int i = 0; i < netntlm->clichall_len; i++)
  {
    u8_to_hex (ptr[i], out_buf + out_len); out_len += 2;
  }

  return out_len;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  // Synthetic self-test and benchmark salts bypass the hash sorter. The
  // fused verifier needs the same one-digest range that the sorter supplies.

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));

  hash->salt->digests_cnt    = 1;
  hash->salt->digests_offset = 0;

  return parser_status;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = module_hash_init_selftest;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;

  // Build the shared schedule before parsing any hash records.

  hc_thread_mutex_lock (nn_tail_lock);

  nn_tail_sched_build ();

  hc_thread_mutex_unlock (nn_tail_lock);
}
