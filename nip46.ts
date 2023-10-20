// import { type Event, finishEvent, nip04, getPublicKey, type EventTemplate, nip26 } from 'nostr-tools'
import { type Event, type EventTemplate, finishEvent } from './event'
import { getPublicKey } from './keys'
import { Filter } from './filter'
import * as nip04 from './nip04'
import * as nip26 from './nip26'
// import { utf8Encoder } from './utils.ts'

// import type { Event } from './event.ts'

export type NostrConnectMetadata = {
    name?: string
    url?: string
    description?: string
    icons?: string[]
}

export type NostrConnect = {
  publicKey: string // the key with whom the connection will be opened
  relay: string // relay where the signer will be connected
  metadata?: NostrConnectMetadata // optional metadata included in opening connection
}

export type Method = 'describe' | 'get_public_key' | 'sign_event' | 'connect' | 'disconnect' | 'delegate' | 'get_relays' | 'nip04_encrypt' | 'nip04_decrypt'

export type Request = {
  id: string,
  method: Method,
  params: any[]
}

export type Response = {
  id: string,
  result?: string | [] | Record<string, any> | Event,
  error?: string
}

export type NcEvent = Event & {
  kind: 24133
}

export type NcEventTemplate = EventTemplate & {
  kind: 24133
}

export function encodeNostrConnect(nostrConnect: NostrConnect): string {
  return `nostrconnect://${nostrConnect.publicKey}?relay=${encodeURIComponent(nostrConnect.relay)}&metadata=${encodeURIComponent(JSON.stringify(nostrConnect.metadata))}`
}

export function decodeNostrConnect(uri: string): NostrConnect | void {
  let uriRegex = /^nostrconnect:\/\/(?<publicKey>[0-9a-fA-F]{64})\?relay=(?<relayURI>[\w%.]+.[\w]+)(&metadata=(?<metadataURI>[^\s]+))?$/
  let validUri = uriRegex.test(uri)
  let uriMatch = uri.match(uriRegex)
  if (!validUri || !uriMatch?.groups ) {
    throw new Error('Invalid NostrConnect URI format')
  }
  try {
    let nostrConnect: NostrConnect = {
      publicKey: uriMatch.groups.publicKey,
      relay: decodeURIComponent(uriMatch.groups.relayURI)
    }
    if (uriMatch.groups.metadataURI) {
      nostrConnect.metadata = JSON.parse(decodeURIComponent(uriMatch.groups.metadataURI))
    }
    return nostrConnect
  } catch (error) {
    throw error
  }
}

type relaySetting = {
  read: boolean,
  write: boolean
}
export class SignerHandler {
  private sk: string;
  private methods: Method[];
  private relays: Record<string, relaySetting>;
  private requestPermitted: (method: Method) => Promise<boolean>

  constructor(secretKey: string, options: {
    methods?: Method[],
    relays?: Record<string, relaySetting>
    requestPermitted?: (method: Method) => Promise<boolean>
  } = {}) {
    this.sk = secretKey
    const defaults = {
      methods: ['describe', 'get_public_key', 'sign_event', 'connect', 'disconnect', 'delegate', 'get_relays', 'nip04_encrypt', 'nip04_decrypt'],
      relays: {},
      requestPermitted: async (method: Method) => { return true }
    }
    const optionsWithDefaults = Object.assign(defaults, options)
    this.methods = optionsWithDefaults.methods
    this.relays = optionsWithDefaults.relays
    this.requestPermitted = optionsWithDefaults.requestPermitted
  }

  async processEvent(event: NcEvent): Promise<NcEvent> {
    const request = JSON.parse(await this.nip04_decrypt(event.content, event.pubkey)) as Request
    const response = await this.requestPermitted(request.method) ? await this.processRequest(request) : {
      id: request.id,
      error: this.responseErrorMessage(request, 'denied permission by user')
    }
    const responseEventTemplate: NcEventTemplate = {
      kind: 24133,
      tags: [['p', event.pubkey]],
      created_at: Math.round(Date.now() / 1000),
      content: await this.nip04_encrypt(JSON.stringify(response), event.pubkey)
    }
    return this.finishEvent(responseEventTemplate)
  }

  async processRequest(request: Request): Promise<Response> {
    const response: Response = {
      id: request.id
    }
    switch (request.method) {
      case 'describe':
        response.result = this.methods
        break;
      case 'get_public_key':
        response.result = getPublicKey(this.sk)
        break;
      case 'sign_event':
        try {
          const eventTemplate = this.getEventTemplateFromRequest(request.params[0])
          response.result = this.finishEvent(eventTemplate)
        } catch (error) {
          response.error = this.responseErrorMessage(request, 'unable to parse the event to be signed')
        }
        break;
      case 'connect':
        response.result = getPublicKey(this.sk)
        break;
      case 'disconnect':
        break;
      case 'delegate':
        try {
          const delegatee: string = request.params[0]
          const delegateeParameters: nip26.Parameters = Object.assign({
            pubkey: delegatee,
          }, request.params[1])
          response.result = nip26.createDelegation(this.sk, delegateeParameters)
        } catch (error) {
          response.error = this.responseErrorMessage(request, 'could not create delegation for the given parameters')
        }
        break;
      case 'get_relays':
        response.result = this.relays
        break;
      case 'nip04_encrypt':
        try {
          const pubkey: string = request.params[0]
          const text: string = request.params[1]
          response.result = await this.nip04_encrypt(text, pubkey)
        } catch (error) {
          response.error = this.responseErrorMessage(request, 'could not encrypt the params in this request')
        }
        break;
      case 'nip04_decrypt':
        try {
          const pubkey: string = request.params[0]
          const cipherText: string = request.params[1]
          response.result = await this.nip04_decrypt(cipherText, pubkey)
        } catch (error) {
          response.error = this.responseErrorMessage(request, 'could not decrypt the params in this request')
        }
        break;
      default:
        response.error = this.responseErrorMessage(request, 'could not parse the method of this request')
    }
    return response
  }

  async nip04_encrypt(text: string, pubkey: string) {
    return await nip04.encrypt(this.sk, pubkey, text)
  }

  async nip04_decrypt(ciphertext: string, pubkey: string) {
    return await nip04.decrypt(this.sk, pubkey, ciphertext)
  }

  finishEvent(event: NcEventTemplate): NcEvent {
    return finishEvent(event, this.sk)
  }

  private responseErrorMessage(request: Request, reason: string): string {
    return `error for ${request.method} request with id ${request.id}: ${reason}`
  }

  private getEventTemplateFromRequest(arg: any): NcEventTemplate {
    if (arg.kind
      && arg.tags
      && arg.content
      && arg.created_at) {
        try {
          const eventTemplate: NcEventTemplate = {
            kind: arg.kind,
            tags: arg.tags,
            content: arg.content,
            created_at: arg.created_at
          }
          return eventTemplate
        } catch (error) {
          throw error
        }
      }
      throw new Error('event parameter could not be parsed')
  }
}

// handler used by happlications
export class AppHandler {
  private appSk: string;
  private appPk: string
  private signerPk: string;

  constructor(appSecretKey: string, signerPublicKey?: string) {
    this.appSk = appSecretKey;
    this.appPk = getPublicKey(this.appSk)
    this.signerPk = signerPublicKey || '';
  }

  async createRequestEvent(request: Request): Promise<NcEvent> {
    let content = await nip04.encrypt(this.appSk, this.signerPk, JSON.stringify(request))
    let event: NcEventTemplate = {
      kind: 24133,
      tags: [],
      created_at: Math.round(Date.now() / 1000),
      content
    }
    if (this.signerPk) event.tags = [['p', this.signerPk]]

    return finishEvent(event, this.appSk)
  }

  async parseEventResponse(event: NcEvent): Promise<Response | null> {
    if (!this.signerPk) return null
    let response: Response = JSON.parse(await nip04.decrypt(this.appSk, this.signerPk, event.content))
    return response
  }

  get filter(): Filter {
    let filter: Filter = {
      kinds: [24133],
      '#p': [this.appPk]
    }
    if (this.signerPk) filter.authors = [this.signerPk]
    return filter
  }

  set signerPublicKey(pk: string) {
    this.signerPk = pk
  }

  get signerPublicKey(): string {
    return this.signerPk;
  }

  get appPublicKey(): string {
    return this.appPk;
  }
}
