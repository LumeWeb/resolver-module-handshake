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
  ResolverModule,
  ResolverOptions,
  resolveSuccess,
} from "@lumeweb/resolver-common";
import { getTld } from "@lumeweb/resolver-common";
import { DNSRecord } from "@lumeweb/resolver-common";

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
    let resolvers = this.resolver.resolvers;
    if (isPromise(resolvers as any)) {
      resolvers = await resolvers;
    }

    for (const resolver of resolvers) {
      let tlds = resolver.getSupportedTlds();
      if (isPromise(tlds as any)) {
        tlds = await tlds;
      }
      tlds.map((item) => blacklist.add(item));
    }

    return blacklist;
  }

  async resolve(
    domain: string,
    options: ResolverOptions,
    bypassCache: boolean
  ): Promise<DNSResult> {
    const tld = getTld(domain);

    const blacklist = await this.buildBlacklist();

    if (blacklist.has(tld)) {
      return resolverEmptyResponse();
    }

    if (isIp(domain)) {
      return resolverEmptyResponse();
    }

    if (options?.options && "subquery" in options.options) {
      return resolverEmptyResponse();
    }

    const chainRecords = await this.query(tld, bypassCache);
    if (!chainRecords) {
      return resolverEmptyResponse();
    }

    let records: DNSRecord[] = [];

    for (const record of chainRecords as HnsRecord[]) {
      switch (record.type) {
        case "NS": {
          await this.processNs(domain, record, records, options, bypassCache);
          break;
        }
        case "GLUE4": {
          await this.processGlue(domain, record, records, options, bypassCache);
          break;
        }
        case "TXT": {
          await this.processTxt(record, records, options);
          break;
        }
        case "SYNTH6": {
          if (
            options.type === DNS_RECORD_TYPE.A &&
            "ipv6" in options.options &&
            options.options.ipv6
          ) {
            records.push({
              type: options.type,
              value: record.address,
            });
          }
          break;
        }
        case "SYNTH4": {
          if (options.type === DNS_RECORD_TYPE.A) {
            records.push({
              type: options.type,
              value: record.address,
            });
          }
          break;
        }
        default: {
          break;
        }
      }
    }

    if (0 < records.length) {
      return resolveSuccess(records);
    }

    return resolverEmptyResponse();
  }

  // @ts-ignore
  private async processNs(
    domain: string,
    record: HnsRecord,
    records: DNSRecord[],
    options: ResolverOptions,
    bypassCache: boolean
  ) {
    if (
      ![DNS_RECORD_TYPE.A, DNS_RECORD_TYPE.CNAME, DNS_RECORD_TYPE.NS].includes(
        options.type
      )
    ) {
      return;
    }
    // @ts-ignore
    const glue = records.slice().find(
      (item: object) =>
        // @ts-ignore
        ["GLUE4", "GLUE6"].includes(item.type) && item.ns === record.ns
    );

    if (glue) {
      return this.processGlue(domain, record, records, options, bypassCache);
    }

    const foundDomain = normalizeDomain(record.ns);
    let isIcann = false;

    let isHip5 = false;

    let hip5Parts = foundDomain.split(".");

    if (
      hip5Parts.length >= 2 &&
      [...options.options?.hip5, ...HIP5_EXTENSIONS].includes(
        hip5Parts[hip5Parts.length - 1]
      )
    ) {
      isHip5 = true;
    }

    if (
      (isDomain(foundDomain) || /[a-zA-Z0-9\-]+/.test(foundDomain)) &&
      !isHip5
    ) {
      if (foundDomain.includes(".")) {
        const tld = foundDomain.split(".")[foundDomain.split(".").length - 1];

        isIcann = tldEnum.list.includes(tld);
      }

      if (!isIcann) {
        const hnsNs = await this.resolver.resolve(foundDomain, options);

        if (hnsNs.records.length) {
          return this.resolver.resolve(domain, {
            ...options,
            options: {
              subquery: true,
              nameserver: hnsNs.records.pop(),
            },
          });
        }
      }

      return this.resolver.resolve(domain, {
        ...options,
        options: { subquery: true, nameserver: foundDomain },
      });
    }

    let result = await this.resolver.resolve(record.ns, options, bypassCache);

    if (!result.records.length) {
      result.records.push({ type: DNS_RECORD_TYPE.NS, value: record.ns });
      return;
    }

    records.push.apply(records, result.records);
  }

  private async processGlue(
    domain: string,
    record: HnsRecord,
    records: DNSRecord[],
    options: ResolverOptions,
    bypassCache: boolean
  ) {
    if (
      ![DNS_RECORD_TYPE.A, DNS_RECORD_TYPE.CNAME, DNS_RECORD_TYPE.NS].includes(
        options.type
      )
    ) {
      return;
    }
    if (isDomain(record.ns) && isIp(record.address)) {
      let results = await this.resolver.resolve(
        domain,
        {
          ...options,
          options: {
            subquery: true,
            nameserver: record.address,
          },
        },
        bypassCache
      );
      if (results.records.length) {
        records.push.apply(records, results.records);
      }
    }
  }

  private async query(tld: string, force: boolean): Promise<[] | boolean> {
    const query = this.resolver.rpcNetwork.query(
      "getnameresource",
      "hns",
      [tld],
      force
    );
    const resp = await query.result;

    // @ts-ignore
    return resp?.records || [];
  }

  private async processTxt(
    record: HnsRecord,
    records: DNSRecord[],
    options: ResolverOptions
  ) {
    const content = record.txt.slice().pop() as string;

    if (
      [DNS_RECORD_TYPE.TEXT, DNS_RECORD_TYPE.CONTENT].includes(options.type)
    ) {
      records.push({
        type: DNS_RECORD_TYPE.TEXT,
        value: content,
      });
    }
  }
}
