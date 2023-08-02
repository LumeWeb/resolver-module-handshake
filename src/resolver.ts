import tldEnum from "@lumeweb/tld-enum";
import {
  AbstractResolverModule,
  DNS_RECORD_TYPE,
  DNSResult,
  isDomain,
  isIp,
  isPromise,
  normalizeDomain,
  resolverEmptyResponse,
  ResolverOptions,
  resolveSuccess,
  ensureUniqueRecords,
  DNSRecord,
  getTld,
  resolverError,
} from "@lumeweb/libresolver";
import {
  createClient,
  Response as HandshakeResponse,
} from "@lumeweb/kernel-handshake-client";
import { ResolverModule } from "@lumeweb/kernel-dns-client";

const client = createClient();

const HIP5_EXTENSIONS = ["eth", "_eth"];

interface HnsRecord {
  type: string;
  address: string;
  txt: string[];
  ns: string;
}

export default class Handshake extends AbstractResolverModule {
  private async buildBlacklist(): Promise<Set<string>> {
    const blacklist = new Set<string>();
    let resolvers = this.resolver.resolvers as unknown as Set<ResolverModule>;
    if (isPromise(resolvers as any)) {
      resolvers = await resolvers;
    }

    for (const resolver of resolvers) {
      let tlds: string[] | Promise<string[]> = resolver.getSupportedTlds();
      if (isPromise(tlds as any)) {
        tlds = await tlds;
      }
      (tlds as string[]).map((item: string) => blacklist.add(item));
    }

    return blacklist;
  }

  async resolve(
    domain: string,
    options: ResolverOptions,
    bypassCache: boolean,
  ): Promise<DNSResult> {
    options.options = options.options || {};
    const tld = getTld(domain);

    const blacklist = await this.buildBlacklist();

    if (blacklist.has(tld)) {
      return resolverEmptyResponse();
    }

    if (isIp(domain)) {
      return resolverEmptyResponse();
    }

    const chainRecords = await this.query(tld);
    if (chainRecords.error) {
      return resolverError(chainRecords.error);
    }

    if (!chainRecords.result?.records.length) {
      return resolverEmptyResponse();
    }

    let records: DNSRecord[] = [];

    const hnsRecords = chainRecords.result?.records;
    const nsServer = this.findNameserver(hnsRecords, options);

    if (!nsServer) {
      const ns = this.findRecordsByType(hnsRecords, "NS");

      if (ns && this.isNSHip5(ns[0], options)) {
        let result = await this.resolver.resolve(
          ns[0].ns,
          {
            ...options,
            options: {
              domain,
            },
          },
          bypassCache,
        );

        if (result.records.length) {
          records.push.apply(records, result.records);
        }
      } else {
        const content = this.findRecordsByType(hnsRecords, "TXT");
        if (content && [DNS_RECORD_TYPE.CONTENT].includes(options.type)) {
          content.forEach((record) =>
            records.push({
              type: DNS_RECORD_TYPE.CONTENT,
              value: record.txt.slice().pop() as string,
            }),
          );
        }
      }
    } else {
      for (const type of [DNS_RECORD_TYPE.A, DNS_RECORD_TYPE.CNAME]) {
        if (type === options.type) {
          const ret = await this.dnsQuery(domain, type);
          if (ret.length) {
            records.push({
              type,
              value: ret.slice().shift().data.address,
            });
          }
        }
      }
    }

    records = ensureUniqueRecords(records);

    if (0 < records.length) {
      return resolveSuccess(records);
    }

    return resolverEmptyResponse();
  }

  private async query(tld: string): Promise<HandshakeResponse> {
    return client.query("getnameresource", [tld, true]);
  }

  private async dnsQuery(domain: string, type: string): Promise<any> {
    return client.dnsQuery(domain, type);
  }

  async ready() {
    return ((await client.status()) as any)?.ready;
  }

  private findNameserver(
    records: HnsRecord[],
    options: ResolverOptions,
  ): HnsRecord | false {
    const synth4 = this.findRecordsByType(records, "SYNTH4");
    const synth6 = this.findRecordsByType(records, "SYNTH6");
    const synth = synth4 || synth6;
    const glue4 = this.findRecordsByType(records, "GLUE4");
    const glue6 = this.findRecordsByType(records, "GLUE6");
    const glue = glue4 || glue6;

    const ns = this.findRecordsByType(records, "NS");

    if (synth) {
      return synth[0];
    }

    if (glue) {
      return glue[0];
    }

    if (ns) {
      if (!this.isNSHip5(ns[0], options)) {
        return ns[0];
      }
    }

    return false;
  }

  private findRecordsByType(
    records: HnsRecord[],
    type: "NS" | "SYNTH4" | "SYNTH6" | "GLUE4" | "GLUE6" | "TXT",
  ) {
    const ret = records.filter((item) => item.type === type);

    if (!ret.length) {
      return false;
    }

    return ret;
  }

  private isNSHip5(record: HnsRecord, options: ResolverOptions) {
    const foundDomain = normalizeDomain(record.ns);

    let hip5Parts = foundDomain.split(".");

    return (
      hip5Parts.length >= 2 &&
      [...(options.options?.hip5 ?? []), ...HIP5_EXTENSIONS].includes(
        hip5Parts[hip5Parts.length - 1],
      )
    );
  }
}
