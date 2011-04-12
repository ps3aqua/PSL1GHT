#ifndef __LV2_HTTP_H__
#define __LV2_HTTP_H__

#include <http/util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct httpClient;
struct httpTransaction;
typedef struct httpClient* httpClientId;
typedef struct httpTransaction* httpTransId;

typedef const void* httpSslId;

typedef struct _https_data
{
	u32 ptr;
	size_t size;
} httpsData;

typedef s32 (*httpAuthenticationCallback)(httpTransId transId,u32 realm,const httpUri *uri,char *username,char *password,bool *save,void *usrArg);
typedef s32 (*httpTransactionStateCallback)(httpTransId transId,u32 state,void *usrArg);
typedef s32 (*httpRedirectCallback)(httpTransId transId,const httpStatusLine *response,const httpUri *from,const httpUri *to,void *usrArg);

s32 httpInit(void *pool,size_t poolSize);
s32 httpEnd(void);

s32 httpsInit(size_t caCertNum,const httpsData *caList);
s32 httpsEnd(void);

s32 httpSetProxy(const httpUri *proxy);
s32 httpGetProxy(httpUri *proxy,void *pool,size_t poolSize,size_t *required);

s32 httpInitCookie(void *pool,size_t poolSize);
s32 httpEndCookie(void);
s32 httpAddCookieWithClientId(const httpUri *uri,const char *cookie,httpClientId clientId);

s32 httpCreateClient(httpClientId *clientId);
s32 httpDestroyClient(httpClientId clientId);

s32 httpClientSetAuthenticationCallback(httpClientId clientId,httpAuthenticationCallback cb,void *usrArg);
s32 httpClientSetTransactionStateCallback(httpClientId clientId,httpTransactionStateCallback cb,void *usrArg);
s32 httpClientSetRedirectCallback(httpClientId clientId,httpRedirectCallback cb,void *usrArg);

s32 httpClientSetProxy(httpClientId clientId,const httpUri *proxy);
s32 httpClientGetProxy(httpClientId clientId,httpUri *proxy,void *pool,size_t poolSize,size_t *required);
s32 httpClientSetVersion(httpClientId clientId,u32 major,u32 minor);
s32 httpClientGetVersion(httpClientId clientId,u32 *major,u32 *minor);

s32 httpClientSetPipeline(httpClientId clientId,u32 enable);
s32 httpClientGetPipeline(httpClientId clientId,u32 *enable);
s32 httpClientSetKeepAlive(httpClientId clientId,u32 enable);
s32 httpClientGetKeepAlive(httpClientId clientId,u32 *enable);
s32 httpClientSetAutoRedirect(httpClientId clientId,u32 enable);
s32 httpClientGetAutoRedirect(httpClientId clientId,u32 *enable);
s32 httpClientSetAutoAuthentication(httpClientId clientId,u32 enable);
s32 httpClientGetAutoAuthentication(httpClientId clientId,u32 *enable);
s32 httpClientSetAuthenticationCacheStatus(httpClientId clientId,u32 enable);
s32 httpClientGetAuthenticationCacheStatus(httpClientId clientId,u32 *enable);
s32 httpClientSetCookieStatus(httpClientId clientId,u32 enable);
s32 httpClientGetCookieStatus(httpClientId clientId,u32 *enable); 

s32 httpClientSetUserAgent(httpClientId clientId,const char *userAgent);
s32 httpClientGetUserAgent(httpClientId clientId,char *userAgent,size_t size,size_t *required);
s32 httpClientSetResponseBufferMax(httpClientId clientId,size_t max);
s32 httpClientGetResponseBufferMax(httpClientId clientId,size_t *max);
// client connection
s32 httpClientCloseAllConnections(httpClientId clientId);
s32 httpClientCloseConnections(httpClientId clientId,const httpUri *uri);
//s32 httpClientPollConnections(httpClientId clientId, httpTransId *transId, u64 usec);
s32 httpClientPollConnections(httpClientId clientId,u32 *transId,u64 usec);
s32 httpClientSetRecvTimeout(httpClientId clientId,u64 usec);
s32 httpClientGetRecvTimeout(httpClientId clientId,u64 *usec);
s32 httpClientSetSendTimeout(httpClientId clientId,u64 usec);
s32 httpClientGetSendTimeout(httpClientId clientId,u64 *usec);
s32 httpClientSetConnTimeout(httpClientId clientId,u64 usec);
s32 httpClientGetConnTimeout(httpClientId clientId,u64 *usec);
s32 httpClientSetTotalPoolSize(httpClientId clientId,size_t poolSize);
s32 httpClientGetTotalPoolSize(httpClientId clientId,size_t *poolSize);
s32 httpClientSetPerHostPoolSize(httpClientId clientId,size_t poolSize);
s32 httpClientGetPerHostPoolSize(httpClientId clientId,size_t *poolSize);
s32 httpClientSetPerHostKeepAliveMax(httpClientId clientId,size_t maxSize);
s32 httpClientGetPerHostKeepAliveMax(httpClientId clientId,size_t *maxSize);
s32 httpClientSetPerPipelineMax(httpClientId clientId,size_t pipeMax);
s32 httpClientGetPerPipelineMax(httpClientId clientId,size_t *pipeMax);
//client header
s32 httpClientGetAllHeaders(httpClientId clientId,httpHeader **headers,size_t *items,void *pool,size_t poolSize,size_t *required);
s32 httpClientSetHeader(httpClientId clientId,const httpHeader *header);
s32 httpClientGetHeader(httpClientId clientId,httpHeader *header,const char *name,void *pool,size_t poolSize,size_t *required);
s32 httpClientAddHeader(httpClientId clientId,const httpHeader *header);
s32 httpClientDeleteHeader(httpClientId clientId,const char *name);
// ssl
//s32 httpClientSetSslCallback(httpClientId clientId, httpsSslCallback cbfunc, void *userArg);
s32 httpClientSetSslClientCertificate(httpClientId clientId,const httpsData *cert,const httpsData *privKey);
/*
// general transactions
s32 httpCreateTransaction(httpTransId *transId, httpClientId clientId, const char *method, const httpUri *uri);
s32 httpDestroyTransaction(httpTransId transId);
s32 httpTransactionGetUri(httpTransId transId, httpUri *uri, void *pool, size_t poolSize, size_t *required);
s32 httpTransactionCloseConnection(httpTransId transId);
s32 httpTransactionReleaseConnection(httpTransId transId, int *sid);
s32 httpTransactionAbortConnection(httpTransId transId);
// transaction request funcs
s32 httpSendRequest(httpTransId transId, const char *buf, size_t size, size_t *sent);
s32 httpRequestSetContentLength(httpTransId transId, u64 totalSize);
s32 httpRequestGetContentLength(httpTransId transId, u64 *totalSize);
s32 httpRequestGetAllHeaders(httpTransId transId, httpHeader **headers, size_t *items, void *pool, size_t poolSize,	size_t *required);
s32 httpRequestSetHeader(httpTransId transId, const httpHeader *header);
s32 httpRequestGetHeader(httpTransId transId, httpHeader *header, const char *name,	void *pool,	size_t poolSize, size_t *required);
s32 httpRequestAddHeader(httpTransId transId, const httpHeader *header);
s32 httpRequestDeleteHeader(httpTransId transId, const char *name);
// transaction response funcs
s32 httpRecvResponse(httpTransId transId, char *buf, size_t size, size_t *recvd);
s32 httpResponseGetAllHeaders(httpTransId transId, httpHeader **headers, size_t *items, void *pool, size_t poolSize, size_t *required);
s32 httpResponseGetHeader(httpTransId transId, httpHeader *header, const char *name, void *pool,	size_t poolSize, size_t *required);
s32 httpResponseGetContentLength(httpTransId transId, u64 *length);
s32 httpResponseGetStatusCode(httpTransId transId, int32_t *code);
s32 httpResponseGetStatusLine(httpTransId transId, httpStatusLine *status, void *pool, size_t poolSize,	size_t *required);
// transaction ssl funcs
s32 httpTransactionGetSslCipherName(httpTransId transId, char *name, size_t size, size_t *required);
s32 httpTransactionGetSslCipherId(httpTransId transId, int32_t *id);
s32 httpTransactionGetSslCipherVersion(httpTransId transId,	char *version, size_t size,	size_t *required);
s32 httpTransactionGetSslCipherBits(httpTransId transId, int32_t *effectiveBits, int32_t *algorithmBits);
s32 httpTransactionGetSslCipherString(httpTransId transId, char *buffer, size_t size);
s32 httpTransactionGetSslVersion(httpTransId transId, int32_t *version);
s32 httpTransactionGetSslId(httpTransId transId, httpSslId *id);
*/
s32 httpCreateTransaction(u32 *transId,httpClientId clientId,const char *method,const httpUri *uri);
s32 httpDestroyTransaction(u32 transId);
s32 httpTransactionGetUri(u32 transId, httpUri *uri,void *pool,size_t poolSize,size_t *required);
s32 httpTransactionCloseConnection(u32 transId);
s32 httpTransactionReleaseConnection(u32 transId,int *sid);
s32 httpTransactionAbortConnection(u32 transId);
// transaction request funcs
s32 httpSendRequest(u32 transId,const char *buf,size_t size,size_t *sent);
s32 httpRequestSetContentLength(u32 transId,u64 totalSize);
s32 httpRequestGetContentLength(u32 transId,u64 *totalSize);
s32 httpRequestGetAllHeaders(u32 transId,httpHeader **headers,size_t *items,void *pool,size_t poolSize,size_t *required);
s32 httpRequestSetHeader(u32 transId,const httpHeader *header);
s32 httpRequestGetHeader(u32 transId,httpHeader *header,const char *name,void *pool,size_t poolSize,size_t *required);
s32 httpRequestAddHeader(u32 transId,const httpHeader *header);
s32 httpRequestDeleteHeader(u32 transId,const char *name);
// transaction response funcs
s32 httpRecvResponse(u32 transId,char *buf,size_t size,size_t *recvd);
s32 httpResponseGetAllHeaders(u32 transId,httpHeader **headers,size_t *items,void *pool,size_t poolSize,size_t *required);
s32 httpResponseGetHeader(u32 transId,httpHeader *header,const char *name,void *pool,size_t poolSize,size_t *required);
s32 httpResponseGetContentLength(u32 transId,u64 *length);
s32 httpResponseGetStatusCode(u32 transId,s32 *code);
s32 httpResponseGetStatusLine(u32 transId,httpStatusLine *status,void *pool,size_t poolSize,size_t *required);
// transaction ssl funcs
s32 httpTransactionGetSslCipherName(u32 transId,char *name,size_t size,size_t *required);
s32 httpTransactionGetSslCipherId(u32 transId, s32 *id);
s32 httpTransactionGetSslCipherVersion(u32 transId,char *version,size_t size,size_t *required);
s32 httpTransactionGetSslCipherBits(u32 transId,s32 *effectiveBits,s32 *algorithmBits);
s32 httpTransactionGetSslCipherString(u32 transId,char *buffer,size_t size);
s32 httpTransactionGetSslVersion(u32 transId,s32 *version);
s32 httpTransactionGetSslId(u32 transId,httpSslId *id);

#ifdef __cplusplus
	}
#endif

#endif
