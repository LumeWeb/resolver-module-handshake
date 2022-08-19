import tldEnum from "@lumeweb/tld-enum";
import { AbstractResolverModule, DNS_RECORD_TYPE, isDomain, isIp, isPromise, normalizeDomain, resolverEmptyResponse, } from "@lumeweb/resolver-common";
import { getTld } from "@lumeweb/resolver-common";
const HIP5_EXTENSIONS = ["eth", "_eth"];
export default class Handshake extends AbstractResolverModule {
    async buildBlacklist() {
        const blacklist = new Set();
        let resolvers = this.resolver.resolvers;
        if (isPromise(resolvers)) {
            resolvers = await resolvers;
        }
        for (const resolver of resolvers) {
            let tlds = resolver.getSupportedTlds();
            if (isPromise(tlds)) {
                tlds = await tlds;
            }
            tlds.map((item) => blacklist.add(item));
        }
        return blacklist;
    }
    async resolve(domain, options, bypassCache) {
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
        let records = [];
        for (const record of chainRecords) {
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
                    if (options.type === DNS_RECORD_TYPE.A &&
                        "ipv6" in options.options &&
                        options.options.ipv6) {
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
        return resolverEmptyResponse();
    }
    // @ts-ignore
    async processNs(domain, record, records, options, bypassCache) {
        if (![DNS_RECORD_TYPE.A, DNS_RECORD_TYPE.CNAME, DNS_RECORD_TYPE.NS].includes(options.type)) {
            return;
        }
        // @ts-ignore
        const glue = records.slice().find((item) => 
        // @ts-ignore
        ["GLUE4", "GLUE6"].includes(item.type) && item.ns === record.ns);
        if (glue) {
            return this.processGlue(domain, record, records, options, bypassCache);
        }
        const foundDomain = normalizeDomain(record.ns);
        let isIcann = false;
        let isHip5 = false;
        let hip5Parts = foundDomain.split(".");
        if (hip5Parts.length >= 2 &&
            [...options.options?.hip5, ...HIP5_EXTENSIONS].includes(hip5Parts[hip5Parts.length - 1])) {
            isHip5 = true;
        }
        if ((isDomain(foundDomain) || /[a-zA-Z0-9\-]+/.test(foundDomain)) &&
            !isHip5) {
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
    async processGlue(domain, record, records, options, bypassCache) {
        if (isDomain(record.ns) && isIp(record.address)) {
            let results = await this.resolver.resolve(domain, {
                ...options,
                options: {
                    subquery: true,
                    nameserver: record.address,
                },
            }, bypassCache);
            if (results.records.length) {
                records.push.apply(records, results.records);
            }
        }
    }
    async query(tld, force) {
        const query = this.resolver.rpcNetwork.query("getnameresource", "hns", [tld], force);
        const resp = await query.result;
        // @ts-ignore
        return resp?.records || [];
    }
    async processTxt(record, records, options) {
        const content = record.txt.slice().pop();
        if ([DNS_RECORD_TYPE.TEXT, DNS_RECORD_TYPE.CONTENT].includes(options.type)) {
            records.push({
                type: DNS_RECORD_TYPE.TEXT,
                value: content,
            });
        }
    }
}
