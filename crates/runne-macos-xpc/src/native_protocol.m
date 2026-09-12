#import <Foundation/Foundation.h>
#include <bsm/audit.h>
#include <stdint.h>
#include <unistd.h>

@protocol RunneCredentialServiceXpcProtocolV1 <NSObject>
- (void)exchange:(NSData *)request reply:(void (^)(NSData *reply))reply;
@end

@protocol RunneQualificationRunnerXpcProtocolV1 <NSObject>
- (void)exchange:(NSData *)request reply:(void (^)(NSData *reply))reply;
@end

Protocol *runne_credential_service_xpc_protocol_v1(void) {
    return @protocol(RunneCredentialServiceXpcProtocolV1);
}

Protocol *runne_qualification_runner_xpc_protocol_v1(void) {
    return @protocol(RunneQualificationRunnerXpcProtocolV1);
}

int runne_xpc_audit_session_identifier(NSXPCConnection *connection) {
    return connection.auditSessionIdentifier;
}

int runne_qualification_runner_current_login_session(
    uint32_t *effective_uid,
    int32_t *audit_session
) {
    if (effective_uid == NULL || audit_session == NULL) {
        return -1;
    }

    auditinfo_addr_t audit = {0};
    if (getaudit_addr(&audit, sizeof(audit)) != 0
        || geteuid() == 0
        || audit.ai_asid <= 0) {
        return -1;
    }
    *effective_uid = geteuid();
    *audit_session = audit.ai_asid;
    return 0;
}
