/*
 * fuzz-stream: pjmedia_stream_create() for a PCMU stream whose codec has an asymmetric encoder ptime.
 *
 * Input: byte 0 is the encoder ptime (ms) the application configures for PCMU (codec manager default
 * param, as pjsua2's CodecParam.encFrameLen does); the rest is the remote SDP answer (its "a=ptime"
 * sets frames-per-packet). The stream is built from SDP exactly as pjsua/pjmedia_session do.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pjlib.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>

static const char LOCAL_SDP[] =
    "v=0\r\n"
    "o=- 1 1 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "c=IN IP4 127.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 4000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n";

static pj_caching_pool caching_pool;
static pjmedia_endpt *endpt;
static pj_pool_t *event_pool;
static int initialized;

static int init_media(void)
{
    if (initialized)
        return 0;

    pj_log_set_level(0);
    if (pj_init() != PJ_SUCCESS)
        return -1;

    pj_caching_pool_init(&caching_pool, &pj_pool_factory_default_policy, 0);
    event_pool = pj_pool_create(&caching_pool.factory, "event", 1000, 1000, NULL);
    if (!event_pool ||
        pjmedia_event_mgr_create(event_pool, PJMEDIA_EVENT_MGR_NO_THREAD, NULL) != PJ_SUCCESS)
        return -1;
    if (pjmedia_endpt_create(&caching_pool.factory, NULL, 0, &endpt) != PJ_SUCCESS)
        return -1;
    if (pjmedia_codec_g711_init(endpt) != PJ_SUCCESS)
        return -1;

    initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    pjmedia_codec_info ci;
    pjmedia_codec_param param;
    pjmedia_codec_mgr *mgr;
    pjmedia_sdp_session *local = NULL, *remote = NULL;
    pjmedia_stream_info si;
    pjmedia_transport *tp = NULL;
    pjmedia_stream *stream = NULL;
    pj_pool_t *pool;
    char *text;
    int rc = -1;

    /* pjlib asserts on a host name of 254+ bytes in a c= line; keep inputs short, as fuzz-sdp.c does. */
    if (Size < 2 || Size > 256 || init_media() != 0)
        return -1;

    pool = pj_pool_create(&caching_pool.factory, "fuzz", 4000, 4000, NULL);
    if (!pool)
        return -1;

    mgr = pjmedia_endpt_get_codec_mgr(endpt);
    pj_bzero(&ci, sizeof(ci));
    ci.type = PJMEDIA_TYPE_AUDIO;
    ci.pt = PJMEDIA_RTP_PT_PCMU;
    ci.encoding_name = pj_str("PCMU");
    ci.clock_rate = 8000;
    ci.channel_cnt = 1;

    if (pjmedia_codec_mgr_get_default_param(mgr, &ci, &param) != PJ_SUCCESS)
        goto done;
    param.info.enc_ptime = Data[0];
    if (pjmedia_codec_mgr_set_default_param(mgr, &ci, &param) != PJ_SUCCESS)
        goto done;

    if (pjmedia_sdp_parse(pool, (char *)LOCAL_SDP, sizeof(LOCAL_SDP) - 1, &local) != PJ_SUCCESS)
        goto done;
    /* The SDP parser expects a NUL-terminated buffer (as fuzz-sdp.c gives it). */
    text = (char *)pj_pool_zalloc(pool, Size);
    memcpy(text, Data + 1, Size - 1);
    if (pjmedia_sdp_parse(pool, text, Size - 1, &remote) != PJ_SUCCESS)
        goto done;
    if (remote->media_count < 1 || pjmedia_sdp_validate(remote) != PJ_SUCCESS)
        goto done;
    if (pjmedia_stream_info_from_sdp(&si, pool, endpt, local, remote, 0) != PJ_SUCCESS)
        goto done;
    if (pjmedia_transport_loop_create(endpt, &tp) != PJ_SUCCESS)
        goto done;

    if (pjmedia_stream_create(endpt, pool, &si, tp, NULL, &stream) == PJ_SUCCESS) {
        pjmedia_stream_destroy(stream);
        rc = 0;
    }

done:
    if (tp)
        pjmedia_transport_close(tp);
    pj_pool_release(pool);
    return rc;
}
