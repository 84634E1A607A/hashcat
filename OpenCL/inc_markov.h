/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_MARKOV_H
#define INC_MARKOV_H

// The base and amplifier kernels enumerate disjoint parts of the mask.
// amp_dst selects where the amplifier word is written. Padding uses the
// full mask length even when the base ends before the amplifier.

#ifdef IS_METAL

#define KERN_ATTR_L_MARKOV                \
  GLOBAL_AS         pw_t *pws_buf_l,      \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
  CONSTANT_AS const u64  &off,            \
  CONSTANT_AS const u32  &pw_l_len,       \
  CONSTANT_AS const u32  &pw_r_len,       \
  CONSTANT_AS const u32  &mask80,         \
  CONSTANT_AS const u32  &bits14,         \
  CONSTANT_AS const u32  &bits15,         \
  CONSTANT_AS const u64  &gid_max,        \
  CONSTANT_AS const u32  &pw_l_term,      \
                    uint3 hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_R_MARKOV                \
  GLOBAL_AS         bf_t *pws_buf_r,      \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
  CONSTANT_AS const u64  &off,            \
  CONSTANT_AS const u32  &pw_r_len,       \
  CONSTANT_AS const u32  &pw_r_css,       \
  CONSTANT_AS const u32  &bits14,         \
  CONSTANT_AS const u32  &bits15,         \
  CONSTANT_AS const u64  &gid_max,        \
                    uint3 hc_gid [[ thread_position_in_grid ]]

#define KERN_ATTR_C_MARKOV                \
  GLOBAL_AS         pw_t *pws_buf,        \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
  CONSTANT_AS const u64  &off,            \
  CONSTANT_AS const u32  &pw_len,         \
  CONSTANT_AS const u32  &mask80,         \
  CONSTANT_AS const u32  &bits14,         \
  CONSTANT_AS const u32  &bits15,         \
  CONSTANT_AS const u64  &gid_max,        \
                    uint3 hc_gid [[ thread_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_L_MARKOV                \
  GLOBAL_AS         pw_t *pws_buf_l,      \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
              const u64   off,            \
              const u32   pw_l_len,       \
              const u32   pw_r_len,       \
              const u32   mask80,         \
              const u32   bits14,         \
              const u32   bits15,         \
              const u64   gid_max,        \
              const u32   pw_l_term

#define KERN_ATTR_R_MARKOV                \
  GLOBAL_AS         bf_t *pws_buf_r,      \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
              const u64   off,            \
              const u32   pw_r_len,       \
              const u32   pw_r_css,       \
              const u32   bits14,         \
              const u32   bits15,         \
              const u64   gid_max

#define KERN_ATTR_C_MARKOV                \
  GLOBAL_AS         pw_t *pws_buf,        \
  GLOBAL_AS   const cs_t *root_css_buf,   \
  GLOBAL_AS   const cs_t *markov_css_buf, \
              const u64   off,            \
              const u32   pw_len,         \
              const u32   mask80,         \
              const u32   bits14,         \
              const u32   bits15,         \
              const u64   gid_max

#endif // IS_METAL

#endif // INC_MARKOV_H

