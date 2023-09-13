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
  async resolve(
    domain: string,
    options: ResolverOptions,
    bypassCache: boolean,
  ): Promise<DNSResult> {
    options.options = options.options || {};

    if (await this.shouldBypassResolution(domain)) {
      return resolverEmptyResponse();
    }

    const chainRecords = await this.query(getTld(domain));
    if (chainRecords.error) {
      return resolverError(chainRecords.error);
    }

    const hnsRecords = chainRecords.result?.records;
    if (!hnsRecords || !hnsRecords.length) {
      return resolverEmptyResponse();
    }

    let records = await this.processRecords(
      hnsRecords,
      options,
      domain,
      bypassCache,
    );
    records = ensureUniqueRecords(records);

    return records.length > 0
      ? resolveSuccess(records)
      : resolverEmptyResponse();
  }

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

  async processRecords(
    hnsRecords: HnsRecord[],
    options: ResolverOptions,
    domain: string,
    bypassCache: boolean,
  ): Promise<DNSRecord[]> {
    let records: DNSRecord[] = [];

    const nsRecords = this.findRecordsByType(hnsRecords, "NS");
    const contentRecords = this.findRecordsByType(hnsRecords, "TXT");

    // Scenario: Content and NS Records Found (HIP-5)
    if (
      nsRecords &&
      contentRecords &&
      options.type === DNS_RECORD_TYPE.CONTENT
    ) {
      return this.handleContentRecords(contentRecords, options);
    }

    // Scenario: HIP-5 Compliance
    if (nsRecords) {
      const hip5Record = nsRecords.find((record) =>
        this.isNSHip5(record, options),
      );
      if (hip5Record) {
        let result = await this.resolver.resolve(
          hip5Record.ns,
          {
            ...options,
            options: {
              domain,
            },
          },
          bypassCache,
        );

        if (result.records.length) {
          records.push(...result.records);
        }
        return records;
      }
    }

    // Scenario: Delegated Lookup (via NS)
    if (nsRecords && this.isNSHip5(nsRecords[0], options)) {
      return await this.handleDelegatedLookup(
        nsRecords,
        options,
        domain,
        bypassCache,
      );
    }

    // Scenario: Content Records
    if (contentRecords) {
      return this.handleContentRecords(contentRecords, options);
    }

    // Scenario: Direct DNS Query
    return await this.handleWithNameserver(domain, options);
  }

  // Handle Content Records
  handleContentRecords(
    contentRecords: HnsRecord[],
    options: ResolverOptions,
  ): DNSRecord[] {
    let records: DNSRecord[] = [];
    if (options.type === DNS_RECORD_TYPE.CONTENT) {
      contentRecords.forEach((record) =>
        records.push({
          type: DNS_RECORD_TYPE.CONTENT,
          value: record.txt?.slice().pop() as string,
        }),
      );
    }
    return records;
  }

  // Handle HIP-5 NS Delegation
  async handleDelegatedLookup(
    nsRecords: HnsRecord[],
    options: ResolverOptions,
    domain: string,
    bypassCache: boolean,
  ): Promise<DNSRecord[]> {
    let records: DNSRecord[] = [];
    const result = await this.resolver.resolve(
      nsRecords[0].ns as string,
      { ...options, options: { domain } },
      bypassCache,
    );

    if (result.records.length) {
      records.push(...result.records);
    }
    return records;
  }

  // Check if the resolution should be bypassed
  async shouldBypassResolution(domain: string): Promise<boolean> {
    const tld = getTld(domain);
    const blacklist = await this.buildBlacklist();
    return blacklist.has(tld) || isIp(domain);
  }

  // Handle the case where a nameserver is found
  async handleWithNameserver(
    domain: string,
    options: ResolverOptions,
  ): Promise<DNSRecord[]> {
    let records: DNSRecord[] = [];

    for (const type of [DNS_RECORD_TYPE.A, DNS_RECORD_TYPE.CNAME]) {
      if (type === options.type) {
        const ret = await this.dnsQuery(domain, type);
        if (ret.length) {
          records.push({ type, value: ret.slice().shift().data.address });
        }
      }
    }

    return records;
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
