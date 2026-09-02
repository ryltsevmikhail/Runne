#import <Foundation/Foundation.h>

@protocol RunneCredentialServiceXpcProtocolV1 <NSObject>
- (void)exchange:(NSData *)request reply:(void (^)(NSData *reply))reply;
@end

Protocol *runne_credential_service_xpc_protocol_v1(void) {
    return @protocol(RunneCredentialServiceXpcProtocolV1);
}
