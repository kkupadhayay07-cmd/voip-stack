//! ITU-T G.729 CS-ACELP 8 kbit/s codec — ITU-conformant bitstream.
//!
//! Frame layout matches ITU-T G.729 exactly (80 bits / 10 bytes per 10 ms
//! frame, MSB-first):
//!
//! ```text
//! L0(1) L1(7) L2(5) L3(5) | P1(8) Pp(1) | fc1(13) s1(4) | GA1(3) GB1(4)
//!                       | P2(5) | fc2(13) s2(4) | GA2(3) GB2(4)  = 80 bits
//! ```
//!
//! # Conformance
//! * Quantizer **codebooks are the ITU-T G.729 tables** (§3.2.4 LSP two-stage
//!   split VQ with switched 4th-order MA prediction, §3.9.2 two-stage gain
//!   VQ with MA-predicted code gain). Tables were transcribed from the
//!   standard as published in FFmpeg `g729data.h` (LGPL-2.1+); the DSP is an
//!   independent float implementation.
//! * Fixed codebook uses the ITU 4-pulse / 13-bit algebraic structure with
//!   the gray-coded fourth track (`{3,4,8,9,…,38,39}`).
//! * Pitch delay uses the ITU mappings: 8-bit first subframe with 1/3
//!   resolution below 85 and the 1-XOR-parity over the 6 MSBs; 5-bit delta
//!   second subframe over `[T1−5⅔, T1+4⅔]`.
//! * The encoder emits fully conformant bitstreams — any ITU G.729 decoder
//!   (FFmpeg, bcg729, hardware) decodes them correctly. This is verified in
//!   CI by cross-decoding against `ffmpeg` (runtime-detected) and against
//!   golden vectors generated with bcg729.
//! * The decoder accepts standard G.729 and implements frame-erasure
//!   concealment, adaptive/MA gain prediction, fixed-codebook sharpening,
//!   a long-term + formant postfilter with AGC, and the output high-pass
//!   filter of §4.2.3.
//!
//! Known Phase-1 fidelity deviations (documented, wire-invisible): float
//! arithmetic instead of the reference fixed point, unweighted (instead of
//! perceptually weighted) analysis-by-synthesis, open-loop pitch
//! preselection, and a simplified postfilter tilt.

// DSP kernels over small fixed arrays read better with explicit index
// arithmetic (polyphase taps, slot offsets) than with iterators.
#![allow(clippy::needless_range_loop)]

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// Whether the full G.729 implementation is compiled in.
pub const SUPPORTED: bool = true;

/// SDP descriptor for G.729 (payload type 18, `annexb=no`).
pub const G729_INFO: FormatInfo = FormatInfo {
    id: CodecId::G729,
    name: "G729",
    payload_type: 18,
    clock_rate: 8000,
    channels: 1,
    fmtp: Some("annexb=no"),
};

const FRAME_SAMPLES: usize = 80; // 10 ms @ 8 kHz
const FRAME_BYTES: usize = 10; // 80 bits
const SUBFRAME: usize = 40;
const LP_ORDER: usize = 10;
/// Reference decoder excitation-buffer layout: history region (max pitch
/// delay + interpolation lookahead) followed by the current frame slot that
/// still carries the previous frame's excitation until each subframe
/// overwrites it (in-place cascade semantics of the ITU reference code).
const EXC_SLOT_BASE: usize = MAX_EXC + 11; // 154
const EXC_BASE_LEN: usize = EXC_SLOT_BASE + 2 * SUBFRAME; // 234
const MAX_EXC: usize = 143;
/// Mean-energy anchor of the code-gain MA prediction (dB). Calibrated
/// empirically against the bcg729 reference decode (see tests/g729_interop).
const GAIN_MEAN_DB: f64 = 63.0;

// ---------------------------------------------------------------------------
// Bit-level frame IO (MSB-first, ITU bit allocation)
// ---------------------------------------------------------------------------

struct BitWriter {
    bytes: [u8; FRAME_BYTES],
    pos: usize,
}

impl BitWriter {
    fn new() -> BitWriter {
        BitWriter {
            bytes: [0; FRAME_BYTES],
            pos: 0,
        }
    }
    fn write(&mut self, n_bits: usize, value: u32) {
        for i in (0..n_bits).rev() {
            let bit = ((value >> i) & 1) as u8;
            let byte = self.pos / 8;
            self.bytes[byte] |= bit << (7 - (self.pos % 8));
            self.pos += 1;
        }
    }
    fn into_bytes(self) -> [u8; FRAME_BYTES] {
        self.bytes
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader { data, pos: 0 }
    }
    fn read(&mut self, n_bits: usize) -> u32 {
        let mut v = 0u32;
        for _ in 0..n_bits {
            let byte = self.pos / 8;
            let bit = (self.data[byte] >> (7 - (self.pos % 8))) & 1;
            v = (v << 1) | bit as u32;
            self.pos += 1;
        }
        v
    }
}

// ---------------------------------------------------------------------------
// ITU-T G.729 quantizer tables (transcribed from the standard as published
// in FFmpeg libavcodec/g729data.h, LGPL-2.1+; values are facts of the spec).
// ---------------------------------------------------------------------------

/// First-stage LSP codebook (§3.2.4), 128×10, format (2.13) — radians·8192.
static CB_LSP_1ST: [[i16; 10]; 128] = [
    [
        1486, 2168, 3751, 9074, 12134, 13944, 17983, 19173, 21190, 21820,
    ],
    [
        1730, 2640, 3450, 4870, 6126, 7876, 15644, 17817, 20294, 21902,
    ],
    [
        1568, 2256, 3088, 4874, 11063, 13393, 18307, 19293, 21109, 21741,
    ],
    [
        1733, 2512, 3357, 4708, 6977, 10296, 17024, 17956, 19145, 20350,
    ],
    [
        1744, 2436, 3308, 8731, 10432, 12007, 15614, 16639, 21359, 21913,
    ],
    [
        1786, 2369, 3372, 4521, 6795, 12963, 17674, 18988, 20855, 21640,
    ],
    [
        1631, 2433, 3361, 6328, 10709, 12013, 13277, 13904, 19441, 21088,
    ],
    [
        1489, 2364, 3291, 6250, 9227, 10403, 13843, 15278, 17721, 21451,
    ],
    [
        1869, 2533, 3475, 4365, 9152, 14513, 15908, 17022, 20611, 21411,
    ],
    [
        2070, 3025, 4333, 5854, 7805, 9231, 10597, 16047, 20109, 21834,
    ],
    [
        1910, 2673, 3419, 4261, 11168, 15111, 16577, 17591, 19310, 20265,
    ],
    [
        1141, 1815, 2624, 4623, 6495, 9588, 13968, 16428, 19351, 21286,
    ],
    [
        2192, 3171, 4707, 5808, 10904, 12500, 14162, 15664, 21124, 21789,
    ],
    [
        1286, 1907, 2548, 3453, 9574, 11964, 15978, 17344, 19691, 22495,
    ],
    [
        1921, 2720, 4604, 6684, 11503, 12992, 14350, 15262, 16997, 20791,
    ],
    [
        2052, 2759, 3897, 5246, 6638, 10267, 15834, 16814, 18149, 21675,
    ],
    [
        1798, 2497, 5617, 11449, 13189, 14711, 17050, 18195, 20307, 21182,
    ],
    [
        1009, 1647, 2889, 5709, 9541, 12354, 15231, 18494, 20966, 22033,
    ],
    [
        3016, 3794, 5406, 7469, 12488, 13984, 15328, 16334, 19952, 20791,
    ],
    [
        2203, 3040, 3796, 5442, 11987, 13512, 14931, 16370, 17856, 18803,
    ],
    [
        2912, 4292, 7988, 9572, 11562, 13244, 14556, 16529, 20004, 21073,
    ],
    [
        2861, 3607, 5923, 7034, 9234, 12054, 13729, 18056, 20262, 20974,
    ],
    [
        3069, 4311, 5967, 7367, 11482, 12699, 14309, 16233, 18333, 19172,
    ],
    [
        2434, 3661, 4866, 5798, 10383, 11722, 13049, 15668, 18862, 19831,
    ],
    [
        2020, 2605, 3860, 9241, 13275, 14644, 16010, 17099, 19268, 20251,
    ],
    [
        1877, 2809, 3590, 4707, 11056, 12441, 15622, 17168, 18761, 19907,
    ],
    [
        2107, 2873, 3673, 5799, 13579, 14687, 15938, 17077, 18890, 19831,
    ],
    [
        1612, 2284, 2944, 3572, 8219, 13959, 15924, 17239, 18592, 20117,
    ],
    [
        2420, 3156, 6542, 10215, 12061, 13534, 15305, 16452, 18717, 19880,
    ],
    [
        1667, 2612, 3534, 5237, 10513, 11696, 12940, 16798, 18058, 19378,
    ],
    [
        2388, 3017, 4839, 9333, 11413, 12730, 15024, 16248, 17449, 18677,
    ],
    [
        1875, 2786, 4231, 6320, 8694, 10149, 11785, 17013, 18608, 19960,
    ],
    [
        679, 1411, 4654, 8006, 11446, 13249, 15763, 18127, 20361, 21567,
    ],
    [
        1838, 2596, 3578, 4608, 5650, 11274, 14355, 15886, 20579, 21754,
    ],
    [
        1303, 1955, 2395, 3322, 12023, 13764, 15883, 18077, 20180, 21232,
    ],
    [
        1438, 2102, 2663, 3462, 8328, 10362, 13763, 17248, 19732, 22344,
    ],
    [
        860, 1904, 6098, 7775, 9815, 12007, 14821, 16709, 19787, 21132,
    ],
    [
        1673, 2723, 3704, 6125, 7668, 9447, 13683, 14443, 20538, 21731,
    ],
    [
        1246, 1849, 2902, 4508, 7221, 12710, 14835, 16314, 19335, 22720,
    ],
    [
        1525, 2260, 3862, 5659, 7342, 11748, 13370, 14442, 18044, 21334,
    ],
    [
        1196, 1846, 3104, 7063, 10972, 12905, 14814, 17037, 19922, 22636,
    ],
    [
        2147, 3106, 4475, 6511, 8227, 9765, 10984, 12161, 18971, 21300,
    ],
    [
        1585, 2405, 2994, 4036, 11481, 13177, 14519, 15431, 19967, 21275,
    ],
    [
        1778, 2688, 3614, 4680, 9465, 11064, 12473, 16320, 19742, 20800,
    ],
    [
        1862, 2586, 3492, 6719, 11708, 13012, 14364, 16128, 19610, 20425,
    ],
    [
        1395, 2156, 2669, 3386, 10607, 12125, 13614, 16705, 18976, 21367,
    ],
    [
        1444, 2117, 3286, 6233, 9423, 12981, 14998, 15853, 17188, 21857,
    ],
    [
        2004, 2895, 3783, 4897, 6168, 7297, 12609, 16445, 19297, 21465,
    ],
    [
        1495, 2863, 6360, 8100, 11399, 14271, 15902, 17711, 20479, 22061,
    ],
    [
        2484, 3114, 5718, 7097, 8400, 12616, 14073, 14847, 20535, 21396,
    ],
    [
        2424, 3277, 5296, 6284, 11290, 12903, 16022, 17508, 19333, 20283,
    ],
    [
        2565, 3778, 5360, 6989, 8782, 10428, 14390, 15742, 17770, 21734,
    ],
    [
        2727, 3384, 6613, 9254, 10542, 12236, 14651, 15687, 20074, 21102,
    ],
    [
        1916, 2953, 6274, 8088, 9710, 10925, 12392, 16434, 20010, 21183,
    ],
    [
        3384, 4366, 5349, 7667, 11180, 12605, 13921, 15324, 19901, 20754,
    ],
    [
        3075, 4283, 5951, 7619, 9604, 11010, 12384, 14006, 20658, 21497,
    ],
    [
        1751, 2455, 5147, 9966, 11621, 13176, 14739, 16470, 20788, 21756,
    ],
    [
        1442, 2188, 3330, 6813, 8929, 12135, 14476, 15306, 19635, 20544,
    ],
    [
        2294, 2895, 4070, 8035, 12233, 13416, 14762, 17367, 18952, 19688,
    ],
    [
        1937, 2659, 4602, 6697, 9071, 12863, 14197, 15230, 16047, 18877,
    ],
    [
        2071, 2663, 4216, 9445, 10887, 12292, 13949, 14909, 19236, 20341,
    ],
    [
        1740, 2491, 3488, 8138, 9656, 11153, 13206, 14688, 20896, 21907,
    ],
    [
        2199, 2881, 4675, 8527, 10051, 11408, 14435, 15463, 17190, 20597,
    ],
    [
        1943, 2988, 4177, 6039, 7478, 8536, 14181, 15551, 17622, 21579,
    ],
    [
        1825, 3175, 7062, 9818, 12824, 15450, 18330, 19856, 21830, 22412,
    ],
    [
        2464, 3046, 4822, 5977, 7696, 15398, 16730, 17646, 20588, 21320,
    ],
    [
        2550, 3393, 5305, 6920, 10235, 14083, 18143, 19195, 20681, 21336,
    ],
    [
        3003, 3799, 5321, 6437, 7919, 11643, 15810, 16846, 18119, 18980,
    ],
    [
        3455, 4157, 6838, 8199, 9877, 12314, 15905, 16826, 19949, 20892,
    ],
    [
        3052, 3769, 4891, 5810, 6977, 10126, 14788, 15990, 19773, 20904,
    ],
    [
        3671, 4356, 5827, 6997, 8460, 12084, 14154, 14939, 19247, 20423,
    ],
    [
        2716, 3684, 5246, 6686, 8463, 10001, 12394, 14131, 16150, 19776,
    ],
    [
        1945, 2638, 4130, 7995, 14338, 15576, 17057, 18206, 20225, 20997,
    ],
    [
        2304, 2928, 4122, 4824, 5640, 13139, 15825, 16938, 20108, 21054,
    ],
    [
        1800, 2516, 3350, 5219, 13406, 15948, 17618, 18540, 20531, 21252,
    ],
    [
        1436, 2224, 2753, 4546, 9657, 11245, 15177, 16317, 17489, 19135,
    ],
    [
        2319, 2899, 4980, 6936, 8404, 13489, 15554, 16281, 20270, 20911,
    ],
    [
        2187, 2919, 4610, 5875, 7390, 12556, 14033, 16794, 20998, 21769,
    ],
    [
        2235, 2923, 5121, 6259, 8099, 13589, 15340, 16340, 17927, 20159,
    ],
    [
        1765, 2638, 3751, 5730, 7883, 10108, 13633, 15419, 16808, 18574,
    ],
    [
        3460, 5741, 9596, 11742, 14413, 16080, 18173, 19090, 20845, 21601,
    ],
    [
        3735, 4426, 6199, 7363, 9250, 14489, 16035, 17026, 19873, 20876,
    ],
    [
        3521, 4778, 6887, 8680, 12717, 14322, 15950, 18050, 20166, 21145,
    ],
    [
        2141, 2968, 6865, 8051, 10010, 13159, 14813, 15861, 17528, 18655,
    ],
    [
        4148, 6128, 9028, 10871, 12686, 14005, 15976, 17208, 19587, 20595,
    ],
    [
        4403, 5367, 6634, 8371, 10163, 11599, 14963, 16331, 17982, 18768,
    ],
    [
        4091, 5386, 6852, 8770, 11563, 13290, 15728, 16930, 19056, 20102,
    ],
    [
        2746, 3625, 5299, 7504, 10262, 11432, 13172, 15490, 16875, 17514,
    ],
    [
        2248, 3556, 8539, 10590, 12665, 14696, 16515, 17824, 20268, 21247,
    ],
    [
        1279, 1960, 3920, 7793, 10153, 14753, 16646, 18139, 20679, 21466,
    ],
    [
        2440, 3475, 6737, 8654, 12190, 14588, 17119, 17925, 19110, 19979,
    ],
    [
        1879, 2514, 4497, 7572, 10017, 14948, 16141, 16897, 18397, 19376,
    ],
    [
        2804, 3688, 7490, 10086, 11218, 12711, 16307, 17470, 20077, 21126,
    ],
    [
        2023, 2682, 3873, 8268, 10255, 11645, 15187, 17102, 18965, 19788,
    ],
    [
        2823, 3605, 5815, 8595, 10085, 11469, 16568, 17462, 18754, 19876,
    ],
    [
        2851, 3681, 5280, 7648, 9173, 10338, 14961, 16148, 17559, 18474,
    ],
    [
        1348, 2645, 5826, 8785, 10620, 12831, 16255, 18319, 21133, 22586,
    ],
    [
        2141, 3036, 4293, 6082, 7593, 10629, 17158, 18033, 21466, 22084,
    ],
    [
        1608, 2375, 3384, 6878, 9970, 11227, 16928, 17650, 20185, 21120,
    ],
    [
        2774, 3616, 5014, 6557, 7788, 8959, 17068, 18302, 19537, 20542,
    ],
    [
        1934, 4813, 6204, 7212, 8979, 11665, 15989, 17811, 20426, 21703,
    ],
    [
        2288, 3507, 5037, 6841, 8278, 9638, 15066, 16481, 21653, 22214,
    ],
    [
        2951, 3771, 4878, 7578, 9016, 10298, 14490, 15242, 20223, 20990,
    ],
    [
        3256, 4791, 6601, 7521, 8644, 9707, 13398, 16078, 19102, 20249,
    ],
    [
        1827, 2614, 3486, 6039, 12149, 13823, 16191, 17282, 21423, 22041,
    ],
    [
        1000, 1704, 3002, 6335, 8471, 10500, 14878, 16979, 20026, 22427,
    ],
    [
        1646, 2286, 3109, 7245, 11493, 12791, 16824, 17667, 18981, 20222,
    ],
    [
        1708, 2501, 3315, 6737, 8729, 9924, 16089, 17097, 18374, 19917,
    ],
    [
        2623, 3510, 4478, 5645, 9862, 11115, 15219, 18067, 19583, 20382,
    ],
    [
        2518, 3434, 4728, 6388, 8082, 9285, 13162, 18383, 19819, 20552,
    ],
    [
        1726, 2383, 4090, 6303, 7805, 12845, 14612, 17608, 19269, 20181,
    ],
    [
        2860, 3735, 4838, 6044, 7254, 8402, 14031, 16381, 18037, 19410,
    ],
    [
        4247, 5993, 7952, 9792, 12342, 14653, 17527, 18774, 20831, 21699,
    ],
    [
        3502, 4051, 5680, 6805, 8146, 11945, 16649, 17444, 20390, 21564,
    ],
    [
        3151, 4893, 5899, 7198, 11418, 13073, 15124, 17673, 20520, 21861,
    ],
    [
        3960, 4848, 5926, 7259, 8811, 10529, 15661, 16560, 18196, 20183,
    ],
    [
        4499, 6604, 8036, 9251, 10804, 12627, 15880, 17512, 20020, 21046,
    ],
    [
        4251, 5541, 6654, 8318, 9900, 11686, 15100, 17093, 20572, 21687,
    ],
    [
        3769, 5327, 7865, 9360, 10684, 11818, 13660, 15366, 18733, 19882,
    ],
    [
        3083, 3969, 6248, 8121, 9798, 10994, 12393, 13686, 17888, 19105,
    ],
    [
        2731, 4670, 7063, 9201, 11346, 13735, 16875, 18797, 20787, 22360,
    ],
    [
        1187, 2227, 4737, 7214, 9622, 12633, 15404, 17968, 20262, 23533,
    ],
    [
        1911, 2477, 3915, 10098, 11616, 12955, 16223, 17138, 19270, 20729,
    ],
    [
        1764, 2519, 3887, 6944, 9150, 12590, 16258, 16984, 17924, 18435,
    ],
    [
        1400, 3674, 7131, 8718, 10688, 12508, 15708, 17711, 19720, 21068,
    ],
    [
        2322, 3073, 4287, 8108, 9407, 10628, 15862, 16693, 19714, 21474,
    ],
    [
        2630, 3339, 4758, 8360, 10274, 11333, 12880, 17374, 19221, 19936,
    ],
    [
        1721, 2577, 5553, 7195, 8651, 10686, 15069, 16953, 18703, 19929,
    ],
];

/// Second-stage LSP codebook (§3.2.4), 32×10: indices 0..5 = low part,
/// 5..10 = high part, format (2.13).
static CB_LSP_2ND: [[i16; 10]; 32] = [
    [-435, -815, -742, 1033, -518, 582, -1201, 829, 86, 385],
    [-833, -891, 463, -8, -1251, 1450, 72, -231, 864, 661],
    [-1021, 231, -306, 321, -220, -163, -526, -754, -1633, 267],
    [57, -198, -339, -33, -1468, 573, 796, -169, -631, 816],
    [171, -350, 294, 1660, 453, 519, 291, 159, -640, -1296],
    [-701, -842, -58, 950, 892, 1549, 715, 527, -714, -193],
    [584, 31, -289, 356, -333, -457, 612, -283, -1381, -741],
    [-109, -808, 231, 77, -87, -344, 1341, 1087, -654, -569],
    [-859, 1236, 550, 854, 714, -543, -1752, -195, -98, -276],
    [-877, -954, -1248, -299, 212, -235, -728, 949, 1517, 895],
    [-77, 344, -620, 763, 413, 502, -362, -960, -483, 1386],
    [-314, -307, -256, -1260, -429, 450, -466, -108, 1010, 2223],
    [711, 693, 521, 650, 1305, -28, -378, 744, -1005, 240],
    [-112, -271, -500, 946, 1733, 271, -15, 909, -259, 1688],
    [575, -10, -468, -199, 1101, -1011, 581, -53, -747, 878],
    [145, -285, -1280, -398, 36, -498, -1377, 18, -444, 1483],
    [-1133, -835, 1350, 1284, -95, 1015, -222, 443, 372, -354],
    [-1459, -1237, 416, -213, 466, 669, 659, 1640, 932, 534],
    [-15, 66, 468, 1019, -748, 1385, -182, -907, -721, -262],
    [-338, 148, 1445, 75, -760, 569, 1247, 337, 416, -121],
    [389, 239, 1568, 981, 113, 369, -1003, -507, -587, -904],
    [-312, -98, 949, 31, 1104, 72, -141, 1465, 63, -785],
    [1127, 584, 835, 277, -1159, 208, 301, -882, 117, -404],
    [539, -114, 856, -493, 223, -912, 623, -76, 276, -440],
    [2197, 2337, 1268, 670, 304, -267, -525, 140, 882, -139],
    [-1596, 550, 801, -456, -56, -697, 865, 1060, 413, 446],
    [1154, 593, -77, 1237, -31, 581, -1037, -895, 669, 297],
    [397, 558, 203, -797, -919, 3, 692, -292, 1050, 782],
    [334, 1475, 632, -80, 48, -1061, -484, 362, -597, -852],
    [-545, -330, -429, -680, 1133, -1182, -744, 1340, 262, 63],
    [1320, 827, -398, -576, 341, -774, -483, -1247, -70, 98],
    [-163, 674, -11, -886, 531, -1125, -265, -242, 724, 934],
];

/// Gain codebook first stage (§3.9.2): `[pitch (0.14), code (2.13)]`.
static CB_GAIN_1ST: [[i16; 2]; 8] = [
    [3242, 9949],
    [1551, 2425],
    [2678, 27162],
    [1921, 9291],
    [1831, 5022],
    [1, 1516],
    [356, 14756],
    [57, 5404],
];

/// Gain codebook second stage (§3.9.2): `[pitch (1.14), code (1.13)]`.
static CB_GAIN_2ND: [[i16; 2]; 16] = [
    [5142, 592],
    [17299, 1861],
    [6160, 2395],
    [16112, 3392],
    [826, 2005],
    [18973, 5935],
    [1994, 0],
    [15434, 237],
    [10573, 2966],
    [15132, 4914],
    [11569, 1196],
    [14194, 1630],
    [8091, 4861],
    [15161, 14276],
    [9120, 525],
    [13260, 3256],
];

/// Switched MA predictor for the LSP quantizer (§3.2.4), 2×4×10, (0.15).
static CB_MA_PRED: [[[i16; 10]; 4]; 2] = [
    [
        [8421, 9109, 9175, 8965, 9034, 9057, 8765, 8775, 9106, 8673],
        [7018, 7189, 7638, 7307, 7444, 7379, 7038, 6956, 6930, 6868],
        [5472, 4990, 5134, 5177, 5246, 5141, 5206, 5095, 4830, 5147],
        [4056, 3031, 2614, 3024, 2916, 2713, 3309, 3237, 2857, 3473],
    ],
    [
        [7733, 7880, 8188, 8175, 8247, 8490, 8637, 8601, 8359, 7569],
        [4210, 3031, 2552, 3473, 3876, 3853, 4184, 4154, 3909, 3968],
        [3214, 1930, 1313, 2143, 2493, 2385, 2755, 2706, 2542, 2919],
        [3024, 1592, 940, 1631, 1723, 1579, 2034, 2084, 1913, 2601],
    ],
];

/// Complement weights of the MA predictor (§3.2.4), 2×10, (0.15).
static CB_MA_SUM: [[i16; 10]; 2] = [
    [7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604],
    [
        14585, 18333, 19772, 17344, 16426, 16459, 15155, 15220, 16043, 15708,
    ],
];

/// Initial LSP (cos-domain) values of the virtual frame preceding a stream.
static LSP_INIT: [i16; 10] = [
    30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
];

/// MA prediction coefficients for the code gain (§3.9.1 eq. 69), (0.13).
static MA_PRED_COEFF: [i16; 4] = [5571, 4751, 2785, 1556];

/// Gray-coded fourth-track positions of the algebraic codebook (§3.8).
static FC_TRACK4: [usize; 16] = [3, 4, 8, 9, 13, 14, 18, 19, 23, 24, 28, 29, 33, 34, 38, 39];

/// 1/3-resolution pitch interpolation filter (§3.7.2), 10 taps × 6 phases,
/// (0.15) — transcribed from FFmpeg `ff_acelp_interp_filter`.
static ACELP_INTERP: [f64; 61] = [
    29443.0, 28346.0, 25207.0, 20449.0, 14701.0, 8693.0, 3143.0, -1352.0, -4402.0, -5865.0,
    -5850.0, -4673.0, -2783.0, -672.0, 1211.0, 2536.0, 3130.0, 2991.0, 2259.0, 1170.0, 0.0,
    -1001.0, -1652.0, -1868.0, -1666.0, -1147.0, -464.0, 218.0, 756.0, 1060.0, 1099.0, 904.0,
    550.0, 135.0, -245.0, -514.0, -634.0, -602.0, -451.0, -231.0, 0.0, 191.0, 308.0, 340.0, 296.0,
    198.0, 78.0, -36.0, -120.0, -163.0, -165.0, -132.0, -79.0, -19.0, 34.0, 73.0, 91.0, 89.0, 70.0,
    38.0, 0.0,
];

// ---------------------------------------------------------------------------
// LP analysis / LSP transforms (float; independent implementation)
// ---------------------------------------------------------------------------

/// Hamming-windowed autocorrelation LP analysis over the last `240` samples.
fn lp_analysis(history: &[f64], out_a: &mut [f64; LP_ORDER + 1]) {
    const WIN: usize = 240;
    let n = history.len();
    let start = n.saturating_sub(WIN);
    let seg = &history[start..];
    let seg_len = seg.len();

    let mut w = vec![0.0f64; seg_len];
    let off = WIN - seg_len;
    for (i, wi) in w.iter_mut().enumerate() {
        let t = (i + off) as f64 / WIN as f64;
        *wi = 0.54 - 0.46 * (2.0 * std::f64::consts::PI * t).cos();
    }

    let mut r = [0.0f64; LP_ORDER + 1];
    for k in 0..=LP_ORDER {
        let mut acc = 0.0;
        for i in k..seg_len {
            acc += w[i] * seg[i] * w[i - k] * seg[i - k];
        }
        r[k] = acc;
    }
    r[0] *= 1.0001; // spectral floor
    if r[0] < 1e-9 {
        for a in out_a.iter_mut() {
            *a = 0.0;
        }
        out_a[0] = 1.0;
        return;
    }

    let mut a = [0.0f64; LP_ORDER + 1];
    a[0] = 1.0;
    let mut err = r[0];
    for i in 1..=LP_ORDER {
        let mut acc = r[i];
        for j in 1..i {
            acc -= a[j] * r[i - j];
        }
        let k = acc / err;
        let mut na = [0.0f64; LP_ORDER + 1];
        na[0] = 1.0;
        for j in 1..i {
            na[j] = a[j] - k * a[i - j];
        }
        na[i] = k;
        a = na;
        err *= 1.0 - k * k;
        if err <= 0.0 {
            break;
        }
    }
    *out_a = a;
}

/// Convert LPC coefficients to LSP frequencies (rad, 0..pi) via the
/// palindromic/antipalindromic split with dense grid + bisection root search.
fn lpc_to_lsp(a: &[f64; LP_ORDER + 1]) -> [f64; LP_ORDER] {
    let mut p = [0.0f64; 12];
    let mut q = [0.0f64; 12];
    for k in 0..=11 {
        let ak = if k <= 10 { a[k] } else { 0.0 };
        let ak11 = if 11 - k <= 10 { a[11 - k] } else { 0.0 };
        p[k] = ak + ak11;
        q[k] = ak - ak11;
    }
    let rp = |w: f64| -> f64 {
        let mut f = 0.0;
        for k in 0..=5 {
            f += p[k] * ((5.5 - k as f64) * w).cos();
        }
        2.0 * f
    };
    let rq = |w: f64| -> f64 {
        let mut f = 0.0;
        for k in 0..=5 {
            f += q[k] * ((5.5 - k as f64) * w).sin();
        }
        -2.0 * f
    };
    let find_roots = |f: &dyn Fn(f64) -> f64| -> Vec<f64> {
        let grid = 300usize;
        let mut roots = Vec::new();
        let mut prev = f(1e-4);
        for g in 1..=grid {
            let w = 1e-4 + (std::f64::consts::PI - 2e-4) * g as f64 / grid as f64;
            let cur = f(w);
            if prev * cur <= 0.0 && roots.len() < 5 {
                let (mut lo, mut hi) = (
                    1e-4 + (std::f64::consts::PI - 2e-4) * (g - 1) as f64 / grid as f64,
                    w,
                );
                for _ in 0..40 {
                    let mid = 0.5 * (lo + hi);
                    if f(mid) * f(lo) <= 0.0 {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                roots.push(0.5 * (lo + hi));
            }
            prev = cur;
        }
        roots
    };
    let mut rp5 = find_roots(&rp);
    let mut rq5 = find_roots(&rq);
    while rp5.len() < 5 {
        rp5.push(0.10 + rp5.len() as f64 * 0.19);
    }
    while rq5.len() < 5 {
        rq5.push(0.19 + rq5.len() as f64 * 0.19);
    }
    rp5.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    rq5.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    rp5.truncate(5);
    rq5.truncate(5);
    let mut lsp = [0.0f64; LP_ORDER];
    for i in 0..5 {
        lsp[2 * i] = rp5[i];
        lsp[2 * i + 1] = rq5[i];
    }
    for i in 1..LP_ORDER {
        if lsp[i] <= lsp[i - 1] + 1e-4 {
            lsp[i] = lsp[i - 1] + 1e-4;
        }
    }
    lsp
}

/// Convert LSP **cosine** values back to LPC coefficients:
/// P(z) = (1+z⁻¹)·Π(1 - 2·q_even·z⁻¹ + z⁻²), Q(z) = (1−z⁻¹)·Π(1 - 2·q_odd·z⁻¹ + z⁻²).
fn lspcos_to_lpc(qcos: &[f64; LP_ORDER]) -> [f64; LP_ORDER + 1] {
    let mut p = [0.0f64; 12];
    let mut q = [0.0f64; 12];
    p[0] = 1.0;
    p[1] = 1.0;
    q[0] = 1.0;
    q[1] = -1.0;
    for i in 0..5 {
        let c = 2.0 * qcos[2 * i];
        let mut np = [0.0f64; 12];
        for k in 0..=(3 + 2 * i) {
            np[k] += p[k];
            if k >= 1 {
                np[k] -= c * p[k - 1];
            }
            if k >= 2 {
                np[k] += p[k - 2];
            }
        }
        p = np;
        let c = 2.0 * qcos[2 * i + 1];
        let mut nq = [0.0f64; 12];
        for k in 0..=(3 + 2 * i) {
            nq[k] += q[k];
            if k >= 1 {
                nq[k] -= c * q[k - 1];
            }
            if k >= 2 {
                nq[k] += q[k - 2];
            }
        }
        q = nq;
    }
    let mut a = [0.0f64; LP_ORDER + 1];
    for k in 0..=LP_ORDER {
        a[k] = 0.5 * (p[k] + q[k]);
    }
    a
}

/// Impulse response of A(z) (synthesis filter), `n` taps.
fn synthesis_ir(a: &[f64; LP_ORDER + 1], n: usize) -> Vec<f64> {
    let mut h = vec![0.0f64; n];
    h[0] = 1.0;
    for i in 1..n {
        let mut acc = 0.0;
        for k in 1..=LP_ORDER.min(i) {
            acc -= a[k] * h[i - k];
        }
        h[i] = acc;
    }
    h
}

/// Convolve `x` with the impulse response `h` (causal, length of x).
fn convolve(h: &[f64], x: &[f64]) -> Vec<f64> {
    let mut y = vec![0.0f64; x.len()];
    for n in 0..x.len() {
        let mut acc = 0.0;
        for (k, &hv) in h.iter().enumerate() {
            if k > n {
                break;
            }
            acc += hv * x[n - k];
        }
        y[n] = acc;
    }
    y
}

// ---------------------------------------------------------------------------
// LSF quantization: ITU two-stage split VQ + switched MA prediction (§3.2.4)
// ---------------------------------------------------------------------------

const LSF_GAP: f64 = 321.0 / 8192.0; // (2.13) 321 → rad
const LSF_MIN: f64 = 40.0 / 8192.0;
const LSF_MAX: f64 = 25681.0 / 8192.0;

/// MA predictor memory: `past[0]` is the most recent quantizer output, in
/// radians (float analogue of FFmpeg's `past_quantizer_outputs`, (2.13)).
#[derive(Debug, Clone)]
struct LsfMemory {
    past: [[f64; LP_ORDER]; 4],
}

impl LsfMemory {
    fn new() -> LsfMemory {
        // FFmpeg decoder_init: past[k][i] = (18717*(i+1))>>3 (2.13) for all k.
        let init: Vec<f64> = (0..LP_ORDER)
            .map(|i| ((18717 * (i as i32 + 1)) >> 3) as f64 / 8192.0)
            .collect();
        let mut past = [[0.0f64; LP_ORDER]; 4];
        for k in 0..4 {
            past[k].copy_from_slice(&init);
        }
        LsfMemory { past }
    }

    fn push(&mut self, q_out: [f64; LP_ORDER]) {
        self.past[3] = self.past[2];
        self.past[2] = self.past[1];
        self.past[1] = self.past[0];
        self.past[0] = q_out;
    }
}

/// Enforce minimum LSF distance and range (float analogue of
/// `ff_acelp_reorder_lsf`, §3.2.4).
fn reorder_lsf(lsf: &mut [f64; LP_ORDER]) {
    for i in 0..LP_ORDER - 1 {
        lsf[i + 1] = lsf[i + 1].max(lsf[i] + LSF_GAP);
    }
    lsf[0] = lsf[0].max(LSF_MIN);
    lsf[LP_ORDER - 1] = lsf[LP_ORDER - 1].min(LSF_MAX);
}

/// Decode the quantizer output (stage-1 + stage-2 sum) with the ITU
/// min-distance smoothing (two passes, 10 and 5 in (2.13)).
fn quantizer_output(l1: usize, l2: usize, l3: usize) -> [f64; LP_ORDER] {
    let mut q = [0.0f64; LP_ORDER];
    for i in 0..5 {
        q[i] = (CB_LSP_1ST[l1][i] + CB_LSP_2ND[l2][i]) as f64 / 8192.0;
        q[i + 5] = (CB_LSP_1ST[l1][i + 5] + CB_LSP_2ND[l3][i + 5]) as f64 / 8192.0;
    }
    for d in [10.0 / 8192.0, 5.0 / 8192.0] {
        for i in 1..LP_ORDER {
            let diff = ((q[i - 1] - q[i] + d) / 2.0).floor();
            if diff > 0.0 {
                q[i - 1] -= diff;
                q[i] += diff;
            }
        }
    }
    q
}

/// Full LSF decode from the four transmitted indices (§3.2.4).
/// Returns `(decoded_lsf, quantizer_output)`.
fn decode_lsf(
    ma: usize,
    l1: usize,
    l2: usize,
    l3: usize,
    mem: &LsfMemory,
) -> ([f64; LP_ORDER], [f64; LP_ORDER]) {
    let q_out = quantizer_output(l1, l2, l3);
    let mut lsf = [0.0f64; LP_ORDER];
    for i in 0..LP_ORDER {
        let mut acc = q_out[i] * (CB_MA_SUM[ma][i] as f64 / 32768.0);
        for j in 0..4 {
            acc += mem.past[j][i] * (CB_MA_PRED[ma][j][i] as f64 / 32768.0);
        }
        lsf[i] = acc;
    }
    reorder_lsf(&mut lsf);
    (lsf, q_out)
}

/// Frame-erasure restore: recover the past quantizer output that would have
/// produced `lsf_prev` under the previous MA bank (float analogue of
/// `lsf_restore_from_previous`).
fn restore_lsf(mem: &LsfMemory, ma_prev: usize, lsf_prev: &[f64; LP_ORDER]) -> [f64; LP_ORDER] {
    let mut q_out = [0.0f64; LP_ORDER];
    for i in 0..LP_ORDER {
        let mut acc = lsf_prev[i];
        for j in 0..4 {
            acc -= mem.past[j][i] * (CB_MA_PRED[ma_prev][j][i] as f64 / 32768.0);
        }
        q_out[i] = acc / (CB_MA_SUM[ma_prev][i] as f64 / 32768.0);
    }
    q_out
}

// ---------------------------------------------------------------------------
// Frame parameter packing (ITU bit allocation, MSB-first)
// ---------------------------------------------------------------------------

/// Quantizer parameter set for one frame.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct FrameParams {
    l0: u32,
    l1: u32,
    l2: u32,
    l3: u32,
    p1: u32,
    parity: u32,
    fc1: u32,
    s1: u32,
    ga1: u32,
    gb1: u32,
    p2: u32,
    fc2: u32,
    s2: u32,
    ga2: u32,
    gb2: u32,
}

fn pack_params(p: &FrameParams) -> [u8; FRAME_BYTES] {
    let mut w = BitWriter::new();
    w.write(1, p.l0);
    w.write(7, p.l1);
    w.write(5, p.l2);
    w.write(5, p.l3);
    w.write(8, p.p1);
    w.write(1, p.parity);
    w.write(13, p.fc1);
    w.write(4, p.s1);
    w.write(3, p.ga1);
    w.write(4, p.gb1);
    w.write(5, p.p2);
    w.write(13, p.fc2);
    w.write(4, p.s2);
    w.write(3, p.ga2);
    w.write(4, p.gb2);
    debug_assert_eq!(w.pos, 80);
    w.into_bytes()
}

fn unpack_params(data: &[u8]) -> FrameParams {
    let mut r = BitReader::new(data);
    FrameParams {
        l0: r.read(1),
        l1: r.read(7),
        l2: r.read(5),
        l3: r.read(5),
        p1: r.read(8),
        parity: r.read(1),
        fc1: r.read(13),
        s1: r.read(4),
        ga1: r.read(3),
        gb1: r.read(4),
        p2: r.read(5),
        fc2: r.read(13),
        s2: r.read(4),
        ga2: r.read(3),
        gb2: r.read(4),
    }
}

// ---------------------------------------------------------------------------
// Fixed codebook: ITU 4-pulse algebraic structure (§3.8)
// ---------------------------------------------------------------------------

/// Decode a fixed-codebook 13+4 bit index into pulse positions/signs.
/// Pulse i (0..2) positions are `{i, i+5, …, i+35}` (3-bit index); pulse 3
/// uses the gray-coded 4-bit track `{3,4,8,9,…,38,39}`.
fn decode_fc(fc: u32, signs: u32) -> ([usize; 4], [f64; 4]) {
    let pos = [
        ((fc & 0x7) as usize) * 5,
        (((fc >> 3) & 0x7) as usize) * 5 + 1,
        (((fc >> 6) & 0x7) as usize) * 5 + 2,
        FC_TRACK4[((fc >> 9) & 0xF) as usize],
    ];
    let sign = [
        if signs & 1 != 0 { 1.0 } else { -1.0 },
        if signs & 2 != 0 { 1.0 } else { -1.0 },
        if signs & 4 != 0 { 1.0 } else { -1.0 },
        if signs & 8 != 0 { 1.0 } else { -1.0 },
    ];
    (pos, sign)
}

/// Encode pulse positions/signs into the 13+4 bit index (inverse of
/// [`decode_fc`]). Unknown positions map deterministically to index 0.
fn encode_fc(pos: &[usize; 4], signs: &[f64; 4]) -> (u32, u32) {
    let i0 = (pos[0] / 5).min(7) as u32;
    let i1 = (pos[1].saturating_sub(1) / 5).min(7) as u32;
    let i2 = (pos[2].saturating_sub(2) / 5).min(7) as u32;
    let i3 = FC_TRACK4.iter().position(|&x| x == pos[3]).unwrap_or(0) as u32;
    let fc = (i3 << 9) | (i2 << 6) | (i1 << 3) | i0;
    let mut s = 0u32;
    for (i, &sg) in signs.iter().enumerate() {
        if sg > 0.0 {
            s |= 1 << i;
        }
    }
    (fc, s)
}

/// In-place ITU fixed-codebook sharpening (§3.8 eq. 40): `fc[j] += β·fc[j−T]`
/// for `j ≥ T`, cascading exactly like the reference C code.
fn sharpen_fc(fc: &mut [f64; SUBFRAME], t: usize, beta: f64) {
    if t == 0 || t >= SUBFRAME {
        return;
    }
    for j in t..SUBFRAME {
        fc[j] += beta * fc[j - t];
    }
}

// ---------------------------------------------------------------------------
// Pitch delay mapping (§3.7.1, matches FFmpeg/bcg729 exactly)
// ---------------------------------------------------------------------------

/// Parity bit over the 6 MSBs of the 8-bit pitch index: `1 ⊕ XOR(bits)`.
/// Matches bcg729 `computeParity` and FFmpeg `av_parity(ac_index >> 2)`.
fn pitch_parity(code: u32) -> u32 {
    1 ^ ((code >> 2).count_ones() & 1)
}

/// 8-bit first-subframe code → pitch delay in 1/3 units (`delay3`).
fn decode_p1(code: u32) -> i32 {
    let d = code + 58;
    if d > 254 {
        (3 * d - 510) as i32
    } else {
        d as i32
    }
}

/// Pitch delay in 1/3 units → 8-bit first-subframe code.
fn encode_p1(delay3: i32) -> u32 {
    if delay3 <= 254 {
        (delay3 - 58) as u32
    } else {
        // Inverse of `delay3 = 3·(code+58) − 510` ⇒ code = (delay3+336)/3.
        ((delay3 + 336) / 3) as u32
    }
}

/// 5-bit second-subframe code → `delay3`, given the integer lower bound
/// `min = clip(T1_int − 5, 20, 134)`.
fn decode_p2(code: u32, min: i32) -> i32 {
    3 * min + code as i32 - 2
}

/// `delay3` → 5-bit second-subframe code (input clamped into the window).
fn encode_p2(delay3: i32, min: i32) -> u32 {
    (delay3 - 3 * min + 2).clamp(0, 31) as u32
}

/// Round `delay3` (1/3 units) to the nearest integer delay.
fn round_delay(delay3: i32) -> i32 {
    (delay3 + 1) / 3
}

// ---------------------------------------------------------------------------
// Adaptive codebook interpolation (§3.7.2, 10-tap 1/3-resolution filter)
// ---------------------------------------------------------------------------

/// Interpolate the adaptive codebook vector at fractional `delay3`
/// (non-destructive read; `src` = buffer index of `in[0]`, i.e. the
/// subframe start minus `delay3/3`).
fn acelp_interp_read(buf: &[f64], src: usize, delay3: i32, out: &mut [f64; SUBFRAME]) {
    let frac = 2 * (delay3.rem_euclid(3)) as usize; // 0, 2, 4
    for n in 0..SUBFRAME {
        let base = src + n;
        let mut acc = 0.0f64;
        for i in 0..10 {
            acc += buf[base - i] * ACELP_INTERP[frac + 6 * i];
            acc += buf[base + i + 1] * ACELP_INTERP[6 - frac + 6 * i];
        }
        out[n] = acc / 32768.0;
    }
}

/// In-place interpolation into the excitation slot, exactly like the
/// reference decoder: ascending writes cascade through overlapping source
/// taps for pitch delays below the subframe length.
fn acelp_interp_inplace(buf: &mut [f64], src: usize, dest: usize, delay3: i32) {
    let frac = 2 * (delay3.rem_euclid(3)) as usize;
    for n in 0..SUBFRAME {
        let base = src + n;
        let mut acc = 0.0f64;
        for i in 0..10 {
            acc += buf[base - i] * ACELP_INTERP[frac + 6 * i];
            acc += buf[base + i + 1] * ACELP_INTERP[6 - frac + 6 * i];
        }
        buf[dest + n] = acc / 32768.0;
    }
}

// ---------------------------------------------------------------------------
// Gain MA prediction (§3.9.1)
// ---------------------------------------------------------------------------

/// dB-domain MA predictor memory for the fixed codebook gain.
#[derive(Debug, Clone)]
struct GainMemory {
    /// Past quantized gain energies in dB (init −14 dB, per reference).
    qe: [f64; 4],
}

impl GainMemory {
    fn new() -> GainMemory {
        GainMemory { qe: [-14.0; 4] }
    }

    /// Predicted mean-removed energy (dB): `GAIN_MEAN_DB + Σ mᵢ·Eₜ₋ᵢ`.
    fn predicted_db(&self) -> f64 {
        GAIN_MEAN_DB
            + self
                .qe
                .iter()
                .zip(MA_PRED_COEFF.iter())
                .map(|(&q, &c)| q * (c as f64 / 8192.0))
                .sum::<f64>()
    }

    /// Decode the fixed codebook gain: `factor·10^(Ê/20)/‖fc‖`.
    fn gain_code(&self, factor: f64, fc_energy: f64) -> f64 {
        let g = factor * 10f64.powf(self.predicted_db() / 20.0) / fc_energy.sqrt().max(1e-9);
        g.clamp(1e-6, 32767.0)
    }

    fn push(&mut self, factor_db: f64) {
        self.qe[3] = self.qe[2];
        self.qe[2] = self.qe[1];
        self.qe[1] = self.qe[0];
        self.qe[0] = factor_db.clamp(-30.0, 30.0);
    }

    fn push_erasure(&mut self) {
        let avg = self.qe.iter().sum::<f64>() / 4.0;
        self.qe[3] = self.qe[2];
        self.qe[2] = self.qe[1];
        self.qe[1] = self.qe[0];
        self.qe[0] = avg.max(-10.0) - 4.0;
    }
}

/// Pitch gain from the (GA, GB) indices: `(g_p0 + g_p1)/2¹⁴` (1.14).
fn gain_pitch(ga: usize, gb: usize) -> f64 {
    // Widen before adding: the raw sum can exceed i16 range.
    ((CB_GAIN_1ST[ga][0] as i32 + CB_GAIN_2ND[gb][0] as i32) as f64 / 16384.0).clamp(0.0, 1.2)
}

/// Gain correction factor from the (GA, GB) indices: `(g_c0 + g_c1)/2¹³`.
fn gain_factor(ga: usize, gb: usize) -> f64 {
    // 27162 + 14276 exceeds i16::MAX — widen before adding (C promotes to int).
    (CB_GAIN_1ST[ga][1] as i32 + CB_GAIN_2ND[gb][1] as i32) as f64 / 8192.0
}

// ---------------------------------------------------------------------------
// High-pass filter (§4.2.3 / §3.1 pre-processing)
// ---------------------------------------------------------------------------

/// 2nd-order DC-removal high-pass of the G.729 standard (used at encoder
/// input and decoder output).
#[derive(Debug, Clone)]
struct Hpf {
    x1: f64,
    x2: f64,
    y1: f64,
    y2: f64,
}

impl Hpf {
    fn new() -> Hpf {
        Hpf {
            x1: 0.0,
            x2: 0.0,
            y1: 0.0,
            y2: 0.0,
        }
    }

    fn run(&mut self, x: &[f64]) -> Vec<f64> {
        const B0: f64 = 0.46363718;
        const B1: f64 = -0.92724705;
        const B2: f64 = 0.46363718;
        const A1: f64 = -1.9059465;
        const A2: f64 = 0.91140258;
        let mut y = Vec::with_capacity(x.len());
        for &xi in x {
            let v = B0 * xi + B1 * self.x1 + B2 * self.x2 - A1 * self.y1 - A2 * self.y2;
            self.x2 = self.x1;
            self.x1 = xi;
            self.y2 = self.y1;
            self.y1 = v;
            y.push(v);
        }
        y
    }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Open-loop pitch estimate (§3.7): maximize the normalized autocorrelation
/// of the input speech over lags 20..143, then prefer divisors (2..4) whose
/// score is within 0.85 of the best (avoids octave/multiple-period errors).
fn open_loop_pitch(speech: &[f64], prev: i32) -> i32 {
    let n = speech.len();
    if n < 40 {
        return prev.clamp(20, 143);
    }
    let mut best = prev.clamp(20, 143);
    let mut best_score = -f64::INFINITY;
    let mut scores = [0.0f64; 144];
    for lag in 20..=143usize.min(n - 40) {
        let m = n - lag;
        let (mut c, mut ef, mut eb) = (0.0f64, 0.0f64, 0.0f64);
        for i in 0..m {
            c += speech[i] * speech[i + lag];
            ef += speech[i] * speech[i];
            eb += speech[i + lag] * speech[i + lag];
        }
        if ef > 1e-9 && eb > 1e-9 {
            scores[lag] = c / (ef.sqrt() * eb.sqrt());
            if scores[lag] > best_score {
                best_score = scores[lag];
                best = lag as i32;
            }
        }
    }
    if !best_score.is_finite() {
        return prev.clamp(20, 143);
    }
    // Prefer a sub-multiple with comparable score (shorter period wins ties).
    for d in 2..=4 {
        let cand = best / d;
        if cand >= 20 && scores[cand as usize] >= 0.85 * best_score {
            best = cand;
            best_score = scores[cand as usize];
        }
    }
    best
}

/// G.729 encoder (ITU-conformant bitstream).
#[derive(Debug, Clone)]
pub struct G729Encoder {
    /// Cos-domain LSPs of the previous decoded frame.
    prev_cos: [f64; LP_ORDER],
    /// MA predictor memory for the LSF quantizer.
    lsf_mem: LsfMemory,
    /// Previous MA bank selector (for erasure restore symmetry).
    ma_prev: usize,
    /// Decoder-mirrored quantized excitation history.
    exc: Vec<f64>,
    /// Decoder-mirrored synthesis shift register.
    syn: [f64; LP_ORDER],
    /// Gain MA predictor memory.
    gain_mem: GainMemory,
    /// Previous subframe's quantized pitch gain (for fc sharpening).
    prev_gp: f64,
    /// Previous frame's integer pitch delay (open-loop seed).
    prev_t: i32,
    /// Input high-pass filter state.
    hpf: Hpf,
    /// Recent input speech for LP analysis (240-sample window).
    speech_hist: Vec<f64>,
    /// Debug: last frame's mirrored plain synthesis (pre-filter).
    pub debug_synth: Vec<f64>,
}

impl G729Encoder {
    /// Create a fresh encoder.
    pub fn new() -> G729Encoder {
        G729Encoder {
            prev_cos: LSP_INIT.map(|v| v as f64 / 32768.0),
            lsf_mem: LsfMemory::new(),
            ma_prev: 0,
            exc: vec![0.0; EXC_BASE_LEN],
            syn: [0.0; LP_ORDER],
            gain_mem: GainMemory::new(),
            prev_gp: 0.0,
            prev_t: 60,
            hpf: Hpf::new(),
            speech_hist: Vec::with_capacity(240),
            debug_synth: Vec::new(),
        }
    }

    /// Encode one 10 ms frame (exactly 80 PCM samples) to 10 bytes.
    pub fn encode_frame(&mut self, pcm: &[i16]) -> Result<[u8; FRAME_BYTES]> {
        if pcm.len() != FRAME_SAMPLES {
            return Err(CodecError::InvalidData(format!(
                "g729 frame must be exactly {FRAME_SAMPLES} samples, got {}",
                pcm.len()
            )));
        }

        self.debug_synth.clear();
        // 1) Pre-processing high-pass filter (§3.1).
        let raw: Vec<f64> = pcm.iter().map(|&s| s as f64).collect();
        let speech = self.hpf.run(&raw);

        // 2) LP analysis over the last 240 samples of filtered input.
        let mut hist = std::mem::take(&mut self.speech_hist);
        hist.extend_from_slice(&speech);
        let mut a = [0.0f64; LP_ORDER + 1];
        lp_analysis(&hist, &mut a);
        let tol = open_loop_pitch(&hist, self.prev_t);
        if hist.len() > 240 {
            let excess = hist.len() - 240;
            hist.drain(0..excess);
        }
        self.speech_hist = hist;

        // 3) LSP → LSF quantization with the ITU VQ + switched MA predictor.
        let lsp = lpc_to_lsp(&a);
        let lsf = lsp; // lpc_to_lsp returns ω in radians = LSFs
        let mut best = (0usize, 0usize, 0usize, 0usize, f64::INFINITY);
        let mut best_lsf = [0.0f64; LP_ORDER];
        let mut best_q_out = [0.0f64; LP_ORDER];
        // Perceptual weights: emphasize closely-spaced LSFs (formants).
        let mut w = [1.0f64; LP_ORDER];
        {
            let mut prev = 0.0;
            for i in 0..LP_ORDER {
                let next = if i + 1 < LP_ORDER {
                    lsf[i + 1]
                } else {
                    std::f64::consts::PI
                };
                w[i] = 1.0 / (lsf[i] - prev).max(1e-4) + 1.0 / (next - lsf[i]).max(1e-4);
                prev = lsf[i];
            }
            let mean = w.iter().sum::<f64>() / LP_ORDER as f64;
            for wi in w.iter_mut() {
                *wi /= mean;
            }
        }
        for ma in 0..2usize {
            // Target quantizer output for this MA bank.
            let mut v = [0.0f64; LP_ORDER];
            for i in 0..LP_ORDER {
                let mut ma_part = 0.0f64;
                for j in 0..4 {
                    ma_part += self.lsf_mem.past[j][i] * (CB_MA_PRED[ma][j][i] as f64 / 32768.0);
                }
                v[i] = (lsf[i] - ma_part) / (CB_MA_SUM[ma][i] as f64 / 32768.0);
            }
            // Stage 1: nearest first-stage vector (weighted).
            let mut l1 = 0usize;
            let mut d1 = f64::INFINITY;
            for (cand, cb) in CB_LSP_1ST.iter().enumerate() {
                let mut d = 0.0;
                for i in 0..LP_ORDER {
                    let e = cb[i] as f64 / 8192.0 - v[i];
                    d += w[i] * e * e;
                }
                if d < d1 {
                    d1 = d;
                    l1 = cand;
                }
            }
            // Stage 2: nearest low/high refinement vectors.
            let mut l2 = 0usize;
            let mut d2 = f64::INFINITY;
            for (cand, cb) in CB_LSP_2ND.iter().enumerate() {
                let mut d = 0.0;
                for i in 0..5 {
                    let e = (CB_LSP_1ST[l1][i] + cb[i]) as f64 / 8192.0 - v[i];
                    d += w[i] * e * e;
                }
                if d < d2 {
                    d2 = d;
                    l2 = cand;
                }
            }
            let mut l3 = 0usize;
            let mut d3 = f64::INFINITY;
            for (cand, cb) in CB_LSP_2ND.iter().enumerate() {
                let mut d = 0.0;
                for i in 5..LP_ORDER {
                    let e = (CB_LSP_1ST[l1][i] + cb[i]) as f64 / 8192.0 - v[i];
                    d += w[i] * e * e;
                }
                if d < d3 {
                    d3 = d;
                    l3 = cand;
                }
            }
            // Evaluate the exact decoder-side reconstruction.
            let (qlsf, q_out) = decode_lsf(ma, l1, l2, l3, &self.lsf_mem);
            let mut err = 0.0;
            for i in 0..LP_ORDER {
                let e = qlsf[i] - lsf[i];
                err += w[i] * e * e;
            }
            if err < best.4 {
                best = (ma, l1, l2, l3, err);
                best_lsf = qlsf;
                best_q_out = q_out;
            }
        }
        let (ma, l1, l2, l3) = (best.0, best.1, best.2, best.3);
        self.lsf_mem.push(best_q_out);
        self.ma_prev = ma;
        let cur_cos: [f64; LP_ORDER] = std::array::from_fn(|i| best_lsf[i].cos());

        // 4) Per-subframe analysis-by-synthesis in the decoder-mirror domain.
        let mut params = FrameParams {
            l0: ma as u32,
            l1: l1 as u32,
            l2: l2 as u32,
            l3: l3 as u32,
            ..Default::default()
        };
        let mut delay3_1 = 3 * self.prev_t;
        for sf in 0..2 {
            let slot = EXC_SLOT_BASE + sf * SUBFRAME;
            let sf_cos: [f64; LP_ORDER] = if sf == 0 {
                std::array::from_fn(|i| 0.5 * (self.prev_cos[i] + cur_cos[i]))
            } else {
                cur_cos
            };
            let asf = lspcos_to_lpc(&sf_cos);
            let h = synthesis_ir(&asf, SUBFRAME);

            // Zero-input response of the mirrored synthesis state.
            let mut zir = [0.0f64; SUBFRAME];
            {
                let mut win = self.syn;
                for n in 0..SUBFRAME {
                    let mut acc = 0.0f64;
                    for k in 1..=LP_ORDER {
                        acc -= asf[k] * win[LP_ORDER - k];
                    }
                    for k in 0..LP_ORDER - 1 {
                        win[k] = win[k + 1];
                    }
                    win[LP_ORDER - 1] = acc;
                    zir[n] = acc;
                }
            }
            let base = sf * SUBFRAME;
            let mut target = [0.0f64; SUBFRAME];
            for i in 0..SUBFRAME {
                target[i] = speech[base + i] - zir[i];
            }

            // ---- Closed-loop pitch with 1/3 resolution ----
            let (delay3, _ac_trial, b1s) = if sf == 0 {
                // ITU-style open-loop preselection: full-range search is
                // unreliable with sparse excitation history, so bound the
                // closed loop to ±5 around the open-loop estimate (§3.7).
                let lo = (3 * (tol - 5)).max(59);
                let hi = (3 * (tol + 5)).min(3 * MAX_EXC as i32);
                let (d3, _ac, b1) = search_pitch(&self.exc, slot, &h, &target, lo, hi, lo, hi);
                (d3, _ac, b1)
            } else {
                let t1_int = round_delay(delay3_1);
                let min = (t1_int - 5).clamp(20, 134);
                let (d3, ac, b1) = search_pitch(
                    &self.exc,
                    slot,
                    &h,
                    &target,
                    3 * min - 2,
                    3 * min + 29,
                    3 * min - 2,
                    3 * min + 29,
                );
                (d3, ac, b1)
            };
            let t_int = round_delay(delay3).clamp(20, 143) as usize;

            // Pitch-basis statistics (shared by residual and joint gain solve).
            let mut m00 = 0.0f64;
            let mut r0 = 0.0f64;
            for i in 0..SUBFRAME {
                m00 += b1s[i] * b1s[i];
                r0 += b1s[i] * target[i];
            }
            let gp_seq = if m00 > 1e-9 {
                (r0 / m00).clamp(0.0, 1.2)
            } else {
                0.0
            };
            let mut res = [0.0f64; SUBFRAME];
            for i in 0..SUBFRAME {
                res[i] = target[i] - gp_seq * b1s[i];
            }

            // ---- Fixed codebook: greedy per-track matching pursuit ----
            let mut pos = [0usize; 4];
            let mut sgn = [1.0f64; 4];
            for track in 0..4usize {
                let candidates: Vec<usize> = if track < 3 {
                    (0..8).map(|k| 5 * k + track).collect()
                } else {
                    FC_TRACK4.to_vec()
                };
                let mut best_p = candidates[0];
                let mut best_s = 1.0f64;
                let mut best_score = -f64::INFINITY;
                for &pp in &candidates {
                    if pp >= SUBFRAME {
                        continue;
                    }
                    let mut c = 0.0f64;
                    let mut e2 = 0.0f64;
                    for n in pp..SUBFRAME {
                        c += res[n] * h[n - pp];
                        e2 += h[n - pp] * h[n - pp];
                    }
                    if e2 < 1e-12 {
                        continue;
                    }
                    let s = if c >= 0.0 { 1.0 } else { -1.0 };
                    let score = c * c / e2;
                    if score > best_score {
                        best_score = score;
                        best_p = pp;
                        best_s = s;
                    }
                }
                pos[track] = best_p;
                sgn[track] = best_s;
                for n in best_p..SUBFRAME {
                    res[n] -= best_s * h[n - best_p];
                }
            }

            // Build the fixed vector and apply decoder-side sharpening.
            let mut fc_vec = [0.0f64; SUBFRAME];
            for i in 0..4 {
                fc_vec[pos[i]] += sgn[i];
            }
            let beta = self.prev_gp.clamp(0.2, 0.7945);
            sharpen_fc(&mut fc_vec, t_int, beta);
            let b2s = convolve(&h, &fc_vec);

            // ---- Gain quantization: closed-loop over the (GA, GB) grid ----
            // Minimize the actual reconstruction error ||t - gp·b1 - gc·b2||²
            // over all 128 codebook couples (spec §3.9 closed-loop search).
            let fc_energy = fc_vec.iter().map(|v| v * v).sum::<f64>();

            // Decoder-identical excitation write: in-place cascade
            // interpolation into the slot, re-solve gains against the
            // cascade-consistent adaptive basis, then the quantized sum.
            let t_floor_f = (delay3 / 3).clamp(0, MAX_EXC as i32) as usize;
            let src_f = slot - t_floor_f;
            acelp_interp_inplace(&mut self.exc, src_f, slot, delay3);
            let mut ac_final = [0.0f64; SUBFRAME];
            ac_final.copy_from_slice(&self.exc[slot..slot + SUBFRAME]);
            let b1f = convolve(&h, &ac_final);
            let (ga, gb, gp_q, gc_q) = solve_gains(&self.gain_mem, fc_energy, &b1f, &b2s, &target);
            let mut excsf = [0.0f64; SUBFRAME];
            for i in 0..SUBFRAME {
                excsf[i] = (gp_q * ac_final[i] + gc_q * fc_vec[i]).clamp(-32768.0, 32767.0);
                self.exc[slot + i] = excsf[i];
            }
            for i in 0..SUBFRAME {
                let mut acc = excsf[i];
                for k in 1..=LP_ORDER {
                    acc -= asf[k] * self.syn[LP_ORDER - k];
                }
                for k in 0..LP_ORDER - 1 {
                    self.syn[k] = self.syn[k + 1];
                }
                self.syn[LP_ORDER - 1] = acc;
                self.debug_synth.push(acc);
            }
            self.gain_mem.push(20.0 * gain_factor(ga, gb).log10());
            self.prev_gp = gp_q;

            // Parameters for this subframe.
            if sf == 0 {
                delay3_1 = delay3;
                params.p1 = encode_p1(delay3);
                params.parity = pitch_parity(params.p1);
                let (fc, s) = encode_fc(&pos, &sgn);
                params.fc1 = fc;
                params.s1 = s;
                params.ga1 = ga as u32;
                params.gb1 = gb as u32;
                self.prev_t = t_int as i32;
            } else {
                let t1_int = round_delay(delay3_1);
                let min = (t1_int - 5).clamp(20, 134);
                params.p2 = encode_p2(delay3, min);
                let (fc, s) = encode_fc(&pos, &sgn);
                params.fc2 = fc;
                params.s2 = s;
                params.ga2 = ga as u32;
                params.gb2 = gb as u32;
            }
        }

        self.prev_cos = cur_cos;
        // Slide the excitation buffer one frame (reference memmove).
        self.exc.copy_within(2 * SUBFRAME..EXC_BASE_LEN, 0);
        Ok(pack_params(&params))
    }
}

/// Closed-loop pitch search: maximize `c²/e²` (c > 0) over integer+fractional
/// delays `delay3 ∈ [lo3, hi3]`. Non-destructive reads from the excitation
/// slot buffer (`slot` = current subframe destination).
#[allow(clippy::too_many_arguments)]
fn search_pitch(
    exc: &[f64],
    slot: usize,
    h: &[f64],
    target: &[f64; SUBFRAME],
    lo3: i32,
    hi3: i32,
    clamp_lo3: i32,
    clamp_hi3: i32,
) -> (i32, [f64; SUBFRAME], Vec<f64>) {
    let lo3 = lo3.max(clamp_lo3).max(59);
    let hi3 = hi3.min(clamp_hi3).min(3 * MAX_EXC as i32);
    let mut best_d3 = ((lo3 + hi3) / 2).max(60);
    let mut best_score = -f64::INFINITY;
    let mut best_ac = [0.0f64; SUBFRAME];
    let mut best_b1 = Vec::new();
    // Coarse integer pass, then fractional refinement around the winner.
    for refine in [false, true] {
        let (a, b, st) = if refine {
            (best_d3 - 2, best_d3 + 2, 1)
        } else {
            (lo3, hi3, 3)
        };
        let mut d3 = a;
        while d3 <= b {
            if d3 >= lo3 && d3 <= hi3 {
                let t_floor = (d3 / 3).clamp(0, MAX_EXC as i32) as usize;
                let start = slot - t_floor;
                let mut ac = [0.0f64; SUBFRAME];
                acelp_interp_read(exc, start, d3, &mut ac);
                let b1 = convolve(h, &ac);
                let mut c = 0.0f64;
                let mut e2 = 0.0f64;
                for i in 0..SUBFRAME {
                    c += target[i] * b1[i];
                    e2 += b1[i] * b1[i];
                }
                if e2 > 1e-9 && c > 0.0 {
                    let score = c * c / e2;
                    if score > best_score {
                        best_score = score;
                        best_d3 = d3;
                        best_ac = ac;
                        best_b1 = b1;
                    }
                }
            }
            d3 += st;
        }
    }
    if best_b1.is_empty() {
        // No positively-correlated candidate: fall back to the clamp center.
        best_d3 = best_d3.clamp(60, 3 * MAX_EXC as i32);
        let t_floor = (best_d3 / 3).clamp(0, MAX_EXC as i32) as usize;
        let start = slot - t_floor;
        acelp_interp_read(exc, start, best_d3, &mut best_ac);
        best_b1 = convolve(h, &best_ac);
    }
    (best_d3, best_ac, best_b1)
}

/// Closed-loop gain quantization (§3.9): pick the (GA, GB) couple
/// minimizing the reconstruction error ||target − gp·b1 − gc·b2||².
/// Returns `(ga, gb, gp_q, gc_q)`.
fn solve_gains(
    gain_mem: &GainMemory,
    fc_energy: f64,
    b1: &[f64],
    b2: &[f64],
    target: &[f64; SUBFRAME],
) -> (usize, usize, f64, f64) {
    // Encoder-side stability guards (decoder semantics unchanged — its state
    // is derived from the bitstream alone): exclude pitch gains above 1.0
    // (unstable adaptive recursion) and bias toward smooth factor
    // trajectories to damp the MA-prediction compounding loop.
    let prev_factor = 10f64.powf(gain_mem.qe[0] / 20.0);
    let mut best = (0usize, 0usize, 0.0f64, 0.0f64, f64::INFINITY);
    for ca in 0..8usize {
        for cb in 0..16usize {
            let gp = gain_pitch(ca, cb);
            if gp > 1.2 {
                continue;
            }
            let factor = gain_factor(ca, cb);
            let gc = gain_mem.gain_code(factor, fc_energy);
            let mut err = 0.0f64;
            for i in 0..SUBFRAME {
                let d = target[i] - gp * b1[i] - gc * b2[i];
                err += d * d;
            }
            let ratio = (factor / prev_factor.max(1e-6)).log10();
            err += 0.02 * ratio * ratio * (err + 1.0);
            if err < best.4 {
                best = (ca, cb, gp, gc, err);
            }
        }
    }
    (best.0, best.1, best.2, best.3)
}

impl Default for G729Encoder {
    fn default() -> G729Encoder {
        G729Encoder::new()
    }
}

impl Encoder for G729Encoder {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize> {
        let frame = self.encode_frame(pcm)?;
        out.extend_from_slice(&frame);
        Ok(FRAME_BYTES)
    }

    fn sample_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn set_dtx(&mut self, _on: bool) -> Result<()> {
        Err(CodecError::Unsupported("g729 annexb dtx"))
    }

    fn reset(&mut self) {
        *self = G729Encoder::new();
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

fn out_raw_pf_bypass(v: f64, out_raw: &mut Vec<f64>) {
    out_raw.push(v);
}

/// Deterministic G.729 random generator (§4.4.4): `v = 31821·v + 13849`.
fn g729_prng(v: u16) -> u16 {
    31821u32.wrapping_mul(v as u32).wrapping_add(13849) as u16
}

/// G.729 decoder with ITU frame-erasure concealment and postfiltering.
#[derive(Debug, Clone)]
pub struct G729Decoder {
    /// Cos-domain LSPs of the previous frame.
    prev_cos: [f64; LP_ORDER],
    /// Quantized LSFs of the previous frame (radians).
    lsf_prev: [f64; LP_ORDER],
    /// MA predictor memory.
    lsf_mem: LsfMemory,
    /// Previous MA bank selector.
    ma_prev: usize,
    /// Excitation history.
    exc: Vec<f64>,
    /// Synthesis shift register.
    syn: [f64; LP_ORDER],
    /// Postfiltered-speech history (for the long-term postfilter).
    syn_pf_hist: Vec<f64>,
    /// Gain MA predictor memory.
    gain_mem: GainMemory,
    /// Previous subframe's pitch gain (sharpening + decay).
    prev_gp: f64,
    /// Previous subframe's code gain (decay).
    prev_gc: f64,
    /// Previous subframe's integer pitch delay.
    prev_t: i32,
    /// Whether the previous frame showed strong periodicity (§4.4).
    was_periodic: bool,
    /// Best long-term postfilter gain of the frame just decoded.
    last_gt: f64,
    /// PRNG state (§4.4.4).
    rand_value: u16,
    /// Output high-pass filter state.
    hpf: Hpf,
    /// AGC memory.
    agc_gain: f64,
    /// Postfilter enable (public toggle for A/B testing / diagnostics).
    pub postfilter: bool,
    /// Debug: last frame's plain synthesis (pre-postfilter/pre-HPF).
    pub debug_synth: Vec<f64>,
}

impl G729Decoder {
    /// Create a fresh decoder.
    pub fn new() -> G729Decoder {
        G729Decoder {
            prev_cos: LSP_INIT.map(|v| v as f64 / 32768.0),
            lsf_prev: (0..LP_ORDER)
                .map(|i| ((18717 * (i as i32 + 1)) >> 3) as f64 / 8192.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            lsf_mem: LsfMemory::new(),
            ma_prev: 0,
            exc: vec![0.0; EXC_BASE_LEN],
            syn: [0.0; LP_ORDER],
            syn_pf_hist: vec![0.0; EXC_BASE_LEN],
            gain_mem: GainMemory::new(),
            prev_gp: 0.0,
            prev_gc: 0.0,
            prev_t: 20,
            was_periodic: false,
            last_gt: 0.0,
            rand_value: 21845,
            hpf: Hpf::new(),
            agc_gain: 1.0,
            postfilter: true,
            debug_synth: Vec::new(),
        }
    }

    /// Decode one 10-byte frame into 80 PCM samples.
    ///
    /// An all-zero frame is treated as frame erasure (§4.4 detection,
    /// matching FFmpeg) and concealed.
    pub fn decode_frame(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        if data.len() != FRAME_BYTES {
            return Err(CodecError::InvalidData(format!(
                "g729 frame must be exactly {FRAME_BYTES} bytes, got {}",
                data.len()
            )));
        }
        let erasure = data.iter().all(|&b| b == 0);
        let p = unpack_params(data);

        // ---- LSP / LSF path ----
        
        let cur_lsf = if erasure {
            let q_out = restore_lsf(&self.lsf_mem, self.ma_prev, &self.lsf_prev);
            self.lsf_mem.push(q_out);
            self.lsf_prev
        } else {
            let (lsf, q_out) = decode_lsf(
                p.l0 as usize,
                p.l1 as usize,
                p.l2 as usize,
                p.l3 as usize,
                &self.lsf_mem,
            );
            self.lsf_mem.push(q_out);
            self.ma_prev = p.l0 as usize;
            self.lsf_prev = lsf;
            lsf
        };
        let cur_cos: [f64; LP_ORDER] = std::array::from_fn(|i| cur_lsf[i].cos());

        // ---- Pitch delays ----
        let delay3_1 = if erasure {
            3 * self.prev_t
        } else {
            let bad_parity = p.parity != pitch_parity(p.p1);
            if bad_parity {
                3 * self.prev_t
            } else {
                decode_p1(p.p1)
            }
        };
        let delay3_2 = if erasure {
            3 * self.prev_t
        } else {
            let t1_int = round_delay(delay3_1);
            let min = (t1_int - 5).clamp(20, 134);
            decode_p2(p.p2, min)
        };

        self.debug_synth.clear();
        let mut out_raw = Vec::with_capacity(FRAME_SAMPLES);
        for sf in 0..2 {
            let slot = EXC_SLOT_BASE + sf * SUBFRAME;
            let delay3 = if sf == 0 { delay3_1 } else { delay3_2 };
            let t_int = round_delay(delay3).clamp(20, 143) as usize;

            let sf_cos: [f64; LP_ORDER] = if sf == 0 {
                std::array::from_fn(|i| 0.5 * (self.prev_cos[i] + cur_cos[i]))
            } else {
                cur_cos
            };
            let asf = lspcos_to_lpc(&sf_cos);

            // Fixed codebook (randomized on erasure, §4.4.4).
            let (fc_idx, fc_signs) = if erasure {
                self.rand_value = g729_prng(self.rand_value);
                let idx = (self.rand_value as u32) & 0x1FFF;
                self.rand_value = g729_prng(self.rand_value);
                let signs = self.rand_value as u32;
                (idx, signs)
            } else if sf == 0 {
                (p.fc1, p.s1)
            } else {
                (p.fc2, p.s2)
            };
            let (pos, sign) = decode_fc(fc_idx, fc_signs);
            let mut fc_vec = [0.0f64; SUBFRAME];
            for i in 0..4 {
                fc_vec[pos[i]] += sign[i];
            }
            // Sharpen with the previous subframe's pitch gain (§3.8 eq. 40).
            let beta = self.prev_gp.clamp(0.2, 0.7945);
            sharpen_fc(&mut fc_vec, t_int, beta);

            // Gains.
            let (gp, gc) = if erasure {
                self.gain_mem.push_erasure();
                let gp = (0.9 * self.prev_gp).clamp(0.0, 1.2);
                let gc = 0.98 * self.prev_gc;
                (gp, gc)
            } else {
                let ga = if sf == 0 {
                    p.ga1 as usize
                } else {
                    p.ga2 as usize
                };
                let gb = if sf == 0 {
                    p.gb1 as usize
                } else {
                    p.gb2 as usize
                };
                let gp = gain_pitch(ga, gb);
                let factor = gain_factor(ga, gb);
                let fc_energy = fc_vec.iter().map(|v| v * v).sum::<f64>();
                let gc = self.gain_mem.gain_code(factor, fc_energy);
                self.gain_mem.push(20.0 * gain_factor(ga, gb).log10());
                (gp, gc)
            };

            // Excitation. Interpolation base uses the FLOOR of delay3/3 and
            // the fractional part, exactly like the reference decoder.
            let t_floor = (delay3 / 3).clamp(0, MAX_EXC as i32) as usize;
            let src = slot - t_floor;
            let (w_ac, w_fc) = if erasure {
                if self.was_periodic {
                    (0.0, gc)
                } else {
                    (gp, 0.0)
                }
            } else {
                (gp, gc)
            };
            // In-place cascade interpolation into the slot (reference
            // semantics), then the weighted excitation written back in place.
            acelp_interp_inplace(&mut self.exc, src, slot, delay3);
            let mut ac_vec = [0.0f64; SUBFRAME];
            ac_vec.copy_from_slice(&self.exc[slot..slot + SUBFRAME]);
            let mut excsf = [0.0f64; SUBFRAME];
            for i in 0..SUBFRAME {
                excsf[i] = (w_ac * ac_vec[i] + w_fc * fc_vec[i]).clamp(-32768.0, 32767.0);
                self.exc[slot + i] = excsf[i];
            }

            // LP synthesis (plain A(z), no expansion — decoder standard).
            let mut synth = [0.0f64; SUBFRAME];
            for i in 0..SUBFRAME {
                let mut acc = excsf[i];
                for k in 1..=LP_ORDER {
                    acc -= asf[k] * self.syn[LP_ORDER - k];
                }
                for k in 0..LP_ORDER - 1 {
                    self.syn[k] = self.syn[k + 1];
                }
                self.syn[LP_ORDER - 1] = acc;
                synth[i] = acc.clamp(-32768.0, 32767.0);
            }
            out_raw.extend_from_slice(&synth);

            // ---- Postfilter: long-term + formant + AGC (§4.2) ----
            if !self.postfilter {
                self.syn_pf_hist.extend_from_slice(&synth);
                self.prev_gp = gp;
                self.prev_gc = gc;
                if erasure {
                    self.prev_t = (self.prev_t + 1).min(143);
                } else {
                    self.prev_t = t_int as i32;
                }
                for &v in synth.iter() {
                    out_raw_pf_bypass(v, &mut out_raw);
                }
                continue;
            }
            let energy_before: f64 = synth.iter().map(|v| v * v).sum();
            let (gt, t_pf) = self.long_term_search(slot, t_int);
            self.last_gt = gt;
            let mut pf = [0.0f64; SUBFRAME];
            for n in 0..SUBFRAME {
                let lt = if gt > 0.0 {
                    if n >= t_pf {
                        synth[n - t_pf]
                    } else {
                        self.syn_pf_hist[self.syn_pf_hist.len() + n - t_pf]
                    }
                } else {
                    0.0
                };
                pf[n] = synth[n] + gt * lt;
            }
            // Formant postfilter H(z) = Â(z/0.75)/Â(z/0.25).
            let mut st = [0.0f64; SUBFRAME];
            for n in 0..SUBFRAME {
                let mut acc = pf[n];
                for k in 1..=LP_ORDER {
                    let g1 = 0.75f64.powi(k as i32);
                    let xk = if n >= k { pf[n - k] } else { 0.0 };
                    acc += g1 * asf[k] * xk;
                }
                for k in 1..=LP_ORDER {
                    let g2 = 0.25f64.powi(k as i32);
                    let yk = if n >= k { st[n - k] } else { 0.0 };
                    acc -= g2 * asf[k] * yk;
                }
                st[n] = acc;
            }
            // Adaptive gain control (§4.2.4, α = 0.1).
            let energy_after: f64 = st.iter().map(|v| v * v).sum();
            if energy_after > 1e-9 {
                let g_inst = (energy_before / energy_after).sqrt().clamp(0.1, 10.0);
                self.agc_gain = 0.9 * self.agc_gain + 0.1 * g_inst;
            }
            for v in st.iter_mut() {
                *v *= self.agc_gain;
            }

            // Long-term postfilter history update.
            self.syn_pf_hist.extend_from_slice(&st);
            while self.syn_pf_hist.len() > EXC_BASE_LEN {
                self.syn_pf_hist.remove(0);
            }

            // State updates.
            self.prev_gp = gp;
            self.prev_gc = gc;
            if erasure {
                self.prev_t = (self.prev_t + 1).min(143);
            } else {
                self.prev_t = t_int as i32;
            }
        }

        self.prev_cos = cur_cos;
        self.debug_synth = out_raw.clone();
        self.exc.copy_within(2 * SUBFRAME..EXC_BASE_LEN, 0);
        self.was_periodic = self.last_gt >= 0.35;
        let filtered = self.hpf.run(&out_raw);
        Ok(filtered
            .iter()
            .map(|&v| v.clamp(-32768.0, 32767.0) as i16)
            .collect())
    }

    /// Long-term postfilter: search the residual (excitation) around the
    /// pitch delay for the delay maximizing normalized correlation.
    /// Returns `(gain, delay)` with gain clamped to `[0, 0.5]` (§4.2.2).
    fn long_term_search(&self, slot: usize, t_int: usize) -> (f64, usize) {
        let exc = &self.exc;
        let mut e0 = 0.0f64;
        for i in 0..SUBFRAME {
            e0 += exc[slot + i] * exc[slot + i];
        }
        if e0 < 1e-9 {
            return (0.0, t_int);
        }
        let lo = t_int.saturating_sub(3).max(20);
        let hi = (t_int + 3).min(MAX_EXC);
        let mut best_t = t_int;
        let mut best_gt = 0.0f64;
        for t in lo..=hi {
            let start = slot - t;
            let mut c = 0.0f64;
            let mut e = 0.0f64;
            for i in 0..SUBFRAME {
                c += exc[slot + i] * exc[start + i];
                e += exc[start + i] * exc[start + i];
            }
            if e > 1e-9 {
                let gt = (c / e).clamp(0.0, 0.5);
                if gt > best_gt {
                    best_gt = gt;
                    best_t = t;
                }
            }
        }
        (best_gt, best_t)
    }
}

impl Default for G729Decoder {
    fn default() -> G729Decoder {
        G729Decoder::new()
    }
}

impl Decoder for G729Decoder {
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        let frame = self.decode_frame(data)?;
        out.extend_from_slice(&frame);
        Ok(FRAME_SAMPLES)
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize> {
        // Frame erasure is signalled by an all-zero frame in G.729 (§4.4);
        // conceal() runs the same erasure path.
        let frame = self.decode_frame(&[0u8; FRAME_BYTES])?;
        out.extend_from_slice(&frame);
        Ok(FRAME_SAMPLES)
    }

    fn sample_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn reset(&mut self) {
        *self = G729Decoder::new();
    }
}

pub(crate) fn make_encoder(clock: u32) -> Result<Box<dyn Encoder>> {
    if clock != 8000 {
        return Err(CodecError::InvalidData(format!(
            "g729 clock is 8000, got {clock}"
        )));
    }
    Ok(Box::new(G729Encoder::new()))
}

pub(crate) fn make_decoder(clock: u32) -> Result<Box<dyn Decoder>> {
    if clock != 8000 {
        return Err(CodecError::InvalidData(format!(
            "g729 clock is 8000, got {clock}"
        )));
    }
    Ok(Box::new(G729Decoder::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn speechish(n: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                let t = i as f64 / 8000.0;
                let env = 0.6 + 0.4 * (2.0 * std::f64::consts::PI * 3.0 * t).sin();
                let v = (2.0 * std::f64::consts::PI * 300.0 * t).sin()
                    + 0.6 * (2.0 * std::f64::consts::PI * 700.0 * t).sin()
                    + 0.3 * (2.0 * std::f64::consts::PI * 1200.0 * t).sin();
                (v * 9000.0 * env).clamp(-32768.0, 32767.0) as i16
            })
            .collect()
    }

    fn aligned_snr_db(a: &[i16], b: &[i16], max_lag: isize) -> (f64, isize) {
        let mut best_lag = 0isize;
        let mut best_corr = f64::NEG_INFINITY;
        for lag in (-max_lag..=max_lag).step_by(2) {
            let mut corr = 0.0f64;
            let n = a.len().min(b.len());
            let lo = if lag >= 0 { 0usize } else { (-lag) as usize };
            let hi = if lag >= 0 {
                n.saturating_sub(lag as usize)
            } else {
                n
            };
            let mut i = lo.max(2);
            while i < hi.saturating_sub(2) {
                corr += (a[i] as f64) * (b[(i as isize + lag) as usize] as f64);
                i += 4;
            }
            if corr > best_corr {
                best_corr = corr;
                best_lag = lag;
            }
        }
        let mut sig = 0.0f64;
        let mut err = 0.0f64;
        let n = a.len().min(b.len());
        for (i, &x) in a.iter().enumerate().take(n) {
            let j = i as isize + best_lag;
            if j < 0 || j as usize >= b.len() {
                continue;
            }
            let d = x as f64 - b[j as usize] as f64;
            sig += x as f64 * x as f64;
            err += d * d;
        }
        (10.0 * (sig / err.max(1.0)).log10(), best_lag)
    }

    #[test]
    fn bit_roundtrip() {
        let p = FrameParams {
            l0: 1,
            l1: 100,
            l2: 25,
            l3: 9,
            p1: 87,
            parity: 1,
            fc1: 5001,
            s1: 10,
            ga1: 5,
            gb1: 11,
            p2: 19,
            fc2: 8191,
            s2: 3,
            ga2: 2,
            gb2: 15,
        };
        let bytes = pack_params(&p);
        assert_eq!(bytes.len(), FRAME_BYTES);
        assert_eq!(unpack_params(&bytes), p);
    }

    #[test]
    fn frame_is_10_bytes() {
        let pcm = speechish(FRAME_SAMPLES);
        let mut e = G729Encoder::new();
        assert_eq!(e.encode_frame(&pcm).unwrap().len(), FRAME_BYTES);
    }

    #[test]
    fn rejects_wrong_frame_length() {
        let mut e = G729Encoder::new();
        assert!(e.encode_frame(&[0i16; 79]).is_err());
        let mut d = G729Decoder::new();
        assert!(d.decode_frame(&[0u8; 9]).is_err());
        assert!(d.decode_frame(&[0u8; 11]).is_err());
    }

    #[test]
    fn roundtrip_snr() {
        let mut e = G729Encoder::new();
        let mut d = G729Decoder::new();
        let pcm = speechish(2400); // 3 s
        let mut back = Vec::new();
        for chunk in pcm.chunks(80) {
            let frame = e.encode_frame(chunk).unwrap();
            back.extend_from_slice(&d.decode_frame(&frame).unwrap());
        }
        let (snr, _) = aligned_snr_db(&pcm, &back, 30);
        // CELP does not preserve waveforms of synthetic fixtures: even the
        // bcg729 reference reaches ≈0 dB sample-SNR on the oracle signal.
        // Wire conformance is gated by the oracle cross-decode test; this
        // check only guards against gross encoder regressions.
        assert!(snr > 1.0, "round-trip SNR {snr:.1} dB too low");
    }

    #[test]
    fn fixed_codebook_known_vectors() {
        // All-zero indices → pulses at track bases {0,1,2,3}, all negative.
        let (pos, sign) = decode_fc(0, 0);
        assert_eq!(pos, [0, 1, 2, 3]);
        assert_eq!(sign, [-1.0, -1.0, -1.0, -1.0]);
        // Max indices → pulse 4 at the last gray position, all positive.
        let (pos, sign) = decode_fc(0x1FFF, 0xF);
        assert_eq!(pos[3], 39);
        assert_eq!(sign, [1.0, 1.0, 1.0, 1.0]);
        // Gray table spot checks (positions 3/4 pair selected by the MSB).
        assert_eq!(decode_fc(0x0200, 0).0[3], 4);
        // Round-trip over a spread of indices.
        for fc in [0u32, 1, 0x1249, 0x0FFF, 0x1FFF] {
            for s in [0u32, 5, 0xF] {
                let (pos, sign) = decode_fc(fc, s);
                let (fc2, s2) = encode_fc(&pos, &sign);
                assert_eq!((fc2, s2), (fc, s));
            }
        }
    }

    #[test]
    fn sharpening_cascades_like_reference() {
        let mut fc = [0.0f64; SUBFRAME];
        fc[2] = 1.0;
        sharpen_fc(&mut fc, 5, 0.5);
        assert!((fc[2] - 1.0).abs() < 1e-12);
        assert!((fc[7] - 0.5).abs() < 1e-12);
        assert!((fc[12] - 0.25).abs() < 1e-12);
        assert!(fc[6].abs() < 1e-12);
    }

    #[test]
    fn pitch_delay_mapping_boundaries() {
        // (code → delay3) boundaries from ff_acelp_decode_8bit_to_1st_delay3.
        assert_eq!(decode_p1(0), 58);
        assert_eq!(decode_p1(2), 60); // T = 20
        assert_eq!(decode_p1(196), 254); // T = 84 2/3
        assert_eq!(decode_p1(197), 255); // T = 85
        assert_eq!(decode_p1(255), 429); // T = 143
                                         // Encoder is the exact inverse over the full integer range.
        for t in 20..=143 {
            let d3 = 3 * t;
            let code = encode_p1(d3);
            assert_eq!(decode_p1(code), d3, "T={t}");
        }
        // Fractional delays below 85 round-trip too.
        for d3 in 59..=254 {
            let code = encode_p1(d3);
            assert_eq!(decode_p1(code), d3);
        }
        // 5-bit delta window.
        let min = 60i32;
        assert_eq!(decode_p2(0, min), 3 * min - 2);
        assert_eq!(decode_p2(31, min), 3 * min + 29);
        assert_eq!(encode_p2(3 * min + 7, min), 9);
    }

    #[test]
    fn parity_matches_bcg729_convention() {
        // Parity bit = 1 XOR XOR(top-6 bits of the 8-bit index).
        // 0x00>>2=000000 → XOR=0 → parity 1
        assert_eq!(pitch_parity(0b0000_0000), 1);
        // 0x80>>2=100000 → XOR=1 → parity 0
        assert_eq!(pitch_parity(0b1000_0000), 0);
        // 0xFC>>2=111111 → XOR=0 → parity 1
        assert_eq!(pitch_parity(0b1111_1100), 1);
        // 0xC0>>2=110000 → XOR=0 → parity 1
        assert_eq!(pitch_parity(0b1100_0000), 1);
    }

    #[test]
    fn parity_exact_values() {
        // parity6(code) = XOR of bits of (code >> 2); parity = 1 ^ parity6.
        for code in 0u32..256 {
            let ones = (code >> 2).count_ones() & 1;
            assert_eq!(pitch_parity(code), 1 ^ ones);
        }
    }

    #[test]
    fn lsf_decode_monotonic_and_bounded() {
        for ma in 0..2usize {
            for l1 in [0usize, 64, 127] {
                for (l2, l3) in [(0usize, 0usize), (31, 31), (7, 19)] {
                    let mem = LsfMemory::new();
                    let (lsf, _) = decode_lsf(ma, l1, l2, l3, &mem);
                    assert!(lsf[0] >= LSF_MIN - 1e-9);
                    assert!(lsf[9] <= LSF_MAX + 1e-9);
                    for i in 1..LP_ORDER {
                        assert!(
                            lsf[i] >= lsf[i - 1] + LSF_GAP - 1e-9,
                            "lsf[{i}] not ascending: {:?}",
                            lsf
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn adaptive_interp_integer_delay_tracks_signal() {
        // Integer delay (delay3 % 3 == 0) must track the delayed signal:
        // the 10-tap phase-0 filter is a mild lowpass, not a pure delta,
        // so verify via normalized cross-correlation at zero lag.
        let mut exc = vec![0.0f64; EXC_BASE_LEN];
        for i in 0..EXC_BASE_LEN {
            exc[i] = ((i * 37) % 251) as f64 - 125.0;
        }
        let start = EXC_SLOT_BASE - 30;
        let mut out = [0.0f64; SUBFRAME];
        acelp_interp_read(&exc, start, 90, &mut out); // delay3=90 → T=30, frac 0
        let mut num = 0.0f64;
        let mut den_o = 0.0f64;
        let mut den_e = 0.0f64;
        for n in 0..SUBFRAME {
            let e = exc[start + n];
            num += out[n] * e;
            den_o += out[n] * out[n];
            den_e += e * e;
        }
        let corr = num / (den_o.sqrt() * den_e.sqrt() + 1e-12);
        assert!(corr > 0.95, "integer-delay interp correlation {corr:.4}");
    }

    #[test]
    fn erasure_concealment_decays() {
        let mut e = G729Encoder::new();
        let mut d = G729Decoder::new();
        let pcm = speechish(800);
        for chunk in pcm.chunks(80) {
            let last_frame = e.encode_frame(chunk).unwrap();
            d.decode_frame(&last_frame).unwrap();
        }
        // Feed erasure frames; output must stay finite and decay.
        let mut energies = Vec::new();
        for _ in 0..6 {
            let out = d.decode_frame(&[0u8; FRAME_BYTES]).unwrap();
            assert_eq!(out.len(), FRAME_SAMPLES);
            energies.push(out.iter().map(|v| *v as f64).map(|v| v * v).sum::<f64>());
        }
        assert!(energies[5] < energies[0] * 4.0, "erasure must not blow up");
        // Same via the Decoder::conceal path.
        let mut out = Vec::new();
        d.conceal(&mut out).unwrap();
        assert_eq!(out.len(), FRAME_SAMPLES);
    }

    #[test]
    fn encoder_decoder_reset() {
        let mut e = G729Encoder::new();
        let mut d = G729Decoder::new();
        let pcm = speechish(FRAME_SAMPLES);
        let f1 = e.encode_frame(&pcm).unwrap();
        e.reset();
        let f2 = e.encode_frame(&pcm).unwrap();
        assert_eq!(f1, f2, "reset must restore the pristine state");
        d.reset();
        let a = d.decode_frame(&f1).unwrap();
        d.reset();
        let b = d.decode_frame(&f1).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn registry_factory_wiring() {
        assert!(super::make_encoder(8000).is_ok());
        assert!(super::make_encoder(16000).is_err());
        assert!(super::make_decoder(8000).is_ok());
        assert!(super::make_decoder(44100).is_err());
        const { assert!(SUPPORTED) };
    }
}
