import {
  AbstractResolverModule,
  DNSResult,
  ResolverOptions,
} from "@lumeweb/libresolver";
export default class Handshake extends AbstractResolverModule {
  private buildBlacklist;
  resolve(
    domain: string,
    options: ResolverOptions,
    bypassCache: boolean
  ): Promise<DNSResult>;
  private processNs;
  private processGlue;
  private query;
  private processTxt;
}
