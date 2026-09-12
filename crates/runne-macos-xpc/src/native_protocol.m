#import <Foundation/Foundation.h>

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
