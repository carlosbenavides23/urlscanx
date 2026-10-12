"""Bounded request-body structure only. Raw values never leave this module."""
from collections import Counter
from email.parser import BytesHeaderParser
from email.policy import default
import json
import re
from urllib.parse import unquote_plus

from .adapters import label, request_body_source
from .model import EvidenceCoverage
from ..display import mask_identifier

MAX_BODY_BYTES = 256 * 1024
MAX_TOTAL_BODY_BYTES = 2 * 1024 * 1024
MAX_FIELDS = 256
MAX_TOTAL_FIELDS = 2048
MAX_DEPTH = 8
MAX_ARRAY_ITEMS = 64
MAX_NAME_CHARS = 80
MAX_PARTS = 64
MAX_PARAMETERS = 256
MAX_HEADER_BYTES = 8192


class Malformed(Exception):
    pass


class Truncated(Exception):
    pass


class Pairs(list):
    """A JSON object with ordered duplicate keys, distinct from an array."""


def field_name(raw):
    safe = label(raw) if len(raw) <= MAX_NAME_CHARS else '[omitted]'
    safe = safe if safe is not None else '[omitted]'
    return safe, safe == raw and safe != '[omitted]'


def field_path(parent, name, array=False):
    if array:
        return parent + '[' + name + ']'
    return parent + ('.' + name if re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', name)
                     else '[' + json.dumps(name, ensure_ascii=True) + ']')


def semantic_role(name):
    # Name-only semantics are deliberately weaker than control/DOM evidence.
    normal = re.sub('[^a-z0-9]', '', name.lower())
    roles = {
        'password':'password', 'passwd':'password', 'email':'email', 'username':'username',
        'loginfmt':'username', 'otp':'otp_candidate', 'passcode':'otp_candidate',
        'verificationcode':'otp_candidate', 'authenticationcode':'otp_candidate',
        'pan':'payment_pan', 'cardnumber':'payment_pan', 'cvc':'payment_cvc', 'cvv':'payment_cvc',
        'cardsecuritycode':'payment_cvc', 'expiry':'payment_expiry', 'expiration':'payment_expiry',
        'phone':'phone', 'telephone':'phone', 'fullname':'person_name', 'firstname':'person_name',
        'lastname':'person_name', 'postalcode':'postal_code', 'zipcode':'postal_code',
        'useragent':'browser_context', 'screen':'browser_context', 'locale':'browser_context',
        'id':'identifier', 'identifier':'identifier',
    }
    return roles.get(normal, 'unknown')


def value_type(value):
    return ('object' if isinstance(value, Pairs) else 'array' if isinstance(value, list) else
            'null' if value is None else 'boolean' if isinstance(value, bool) else
            'number' if isinstance(value, (int,float)) else 'string')


def add_field(fields, raw_name, path, kind, *, matchable=True, filename_present=False, content_type=None):
    if len(fields) >= MAX_FIELDS:
        raise Truncated('decoded fields budget')
    name, safe = field_name(raw_name)
    fields.append({'path':path, 'name':name, 'normalized_name':re.sub('[^a-z0-9]', '', name.lower()),
                   'value_type':kind, 'semantic_role':semantic_role(name),
                   'semantic_basis':'field_name_only', 'value_state':'present_omitted',
                   'redaction':{'values_omitted':True, 'fingerprinting':'not_performed'},
                   'structural_matchable':matchable and safe,
                   'filename_present':filename_present, 'filename':'[omitted]' if filename_present else None,
                   'part_media_type':content_type})


def json_fields(body):
    # Preflight nesting before json.loads to avoid unbounded Python recursion.
    depth = 0
    quoted = escape = False
    for ch in body:
        if quoted:
            if escape: escape = False
            elif ch == '\\': escape = True
            elif ch == '"': quoted = False
        elif ch == '"': quoted = True
        elif ch in '[{':
            depth += 1
            if depth > MAX_DEPTH + 1: raise Truncated('nesting depth budget')
        elif ch in ']}': depth -= 1
    try:
        root = json.loads(body, object_pairs_hook=Pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Malformed()))
    except (ValueError, RecursionError) as exc:
        raise Malformed() from exc
    fields = []
    def walk(value, path, depth=0, matchable=True):
        if depth > MAX_DEPTH: raise Truncated('nesting depth budget')
        if isinstance(value, Pairs):
            if len(value) > MAX_PARAMETERS: raise Truncated('parameter count budget')
            for name, child in value:
                safe, exact = field_name(name)
                child_path = field_path(path,safe)
                add_field(fields,name,child_path,value_type(child),matchable=matchable)
                walk(child,child_path,depth+1,matchable and exact)
        elif isinstance(value,list):
            if len(value) > MAX_ARRAY_ITEMS: raise Truncated('array items budget')
            for i,child in enumerate(value):
                child_path = field_path(path,str(i),True)
                add_field(fields,str(i),child_path,value_type(child),matchable=matchable)
                walk(child,child_path,depth+1,matchable)
    if isinstance(root,(Pairs,list)):
        walk(root,'$')
    else:
        add_field(fields,'','$',value_type(root),matchable=False)
    return fields


def form_fields(body):
    pieces = body.split('&') if body else []
    if len(pieces) > MAX_PARAMETERS: raise Truncated('parameter count budget')
    fields = []
    for part in pieces:
        if re.search(r'%(?![0-9A-Fa-f]{2})',part): raise Malformed()
        raw_name, sep, raw_value = part.partition('=')
        # Validate both sides strictly; values are discarded, never retained.
        try:
            name = unquote_plus(raw_name,encoding='utf8',errors='strict')
            unquote_plus(raw_value,encoding='utf8',errors='strict')
        except UnicodeError as exc:
            raise Malformed() from exc
        safe,_ = field_name(name)
        add_field(fields,name,field_path('$',safe),'string')
    return fields


def media_type(value):
    if not isinstance(value,str): return None
    media = value.split(';',1)[0].strip().lower()
    if not re.fullmatch(r'[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+',media) or len(media)>80:
        return None
    return media if all(mask_identifier(part, fingerprint=False)==part for part in media.split('/')) else None


def multipart_fields(body, content_type):
    # Parse only MIME headers and delimiters; uploaded contents stay opaque.
    headers = BytesHeaderParser(policy=default).parsebytes(('Content-Type: '+content_type+'\r\n\r\n').encode('ascii'))
    boundary = headers.get_boundary()
    if not boundary or not re.fullmatch(r"[0-9A-Za-z'()+_,./:=?-]{1,70}",boundary): raise Malformed()
    marker = '--'+boundary
    # Delimiters must occupy complete CRLF lines. Boundary text within content
    # does not count as a part delimiter.
    if not body.startswith(marker+'\r\n') or not body.endswith('\r\n'+marker+'--\r\n'):
        raise Malformed()
    parts = body[len(marker)+2:-(len(marker)+6)].split('\r\n'+marker+'\r\n')
    if len(parts)>MAX_PARTS: raise Truncated('multipart parts budget')
    fields=[]
    for part in parts:
        head,sep,_ = part.partition('\r\n\r\n')
        if not sep: raise Malformed()
        if len(head.encode('utf8'))>MAX_HEADER_BYTES: raise Truncated('multipart header bytes budget')
        try:
            parsed=BytesHeaderParser(policy=default).parsebytes(head.encode('ascii')+b'\r\n\r\n')
        except UnicodeError as exc: raise Malformed() from exc
        if parsed.defects or len(parsed.get_all('Content-Disposition',[]))!=1: raise Malformed()
        if parsed['Content-Disposition'].defects: raise Malformed()
        parameters=parsed.get_params(header='Content-Disposition') or []
        if sum(k.lower()=='name' for k,_ in parameters)!=1 or sum(k.lower()=='filename' for k,_ in parameters)>1:
            raise Malformed()
        if parsed.get_content_disposition()!='form-data': raise Malformed()
        name=parsed.get_param('name',header='Content-Disposition')
        if not isinstance(name,str): raise Malformed()
        filename=parsed.get_param('filename',header='Content-Disposition')
        safe,_=field_name(name)
        add_field(fields,name,field_path('$',safe),'file' if filename is not None else 'string',
                  filename_present=filename is not None,content_type=media_type(parsed.get('Content-Type')))
    return fields


def parse_body(body, content_type):
    media=media_type(content_type)
    if not body: return [],'empty','parsed'
    if media=='application/json' or media and media.endswith('+json'):
        return json_fields(body),'json','parsed'
    if media=='application/x-www-form-urlencoded':
        return form_fields(body),'form_urlencoded','parsed'
    if media=='multipart/form-data':
        return multipart_fields(body,content_type),'multipart','parsed'
    return [],'unresolved' if media is None else 'opaque','unsupported'


def inventory(result,events,registry):
    output=registry.analysis
    total=0
    total_fields=0
    counts=Counter()
    for event in events:
        source=request_body_source(result,event)
        pointer=source['pointer']
        # Never return header contents except a validated media type.
        headers=source['headers']
        headers_truncated = len(headers) > MAX_PARAMETERS
        if headers_truncated:
            headers={}
        ctypes=[v for k,v in headers.items() if isinstance(k,str) and k.lower()=='content-type']
        encodings=[v for k,v in headers.items() if isinstance(k,str) and k.lower()=='content-encoding']
        ctype_oversized = len(ctypes)==1 and isinstance(ctypes[0],str) and len(ctypes[0])>MAX_HEADER_BYTES
        ctype=ctypes[0] if len(ctypes)==1 and isinstance(ctypes[0],str) and not ctype_oversized and '\r' not in ctypes[0] and '\n' not in ctypes[0] else None
        media=media_type(ctype)
        fields=[];reason=None;fmt='unresolved';status='not_run';availability='unavailable'
        if media=='application/json' or media and media.endswith('+json'): fmt='json'
        elif media=='application/x-www-form-urlencoded': fmt='form_urlencoded'
        elif media=='multipart/form-data': fmt='multipart'
        elif media: fmt='opaque'
        body=source['body']
        preserved=False
        body_pointer=pointer+'/postData' if source['literal_present'] else pointer+'/postDataEntries'
        if source['literal_present'] and isinstance(body,str):
            preserved=True
            try:
                if len(body)>MAX_BODY_BYTES: raise Truncated('body bytes budget')
                size=len(body.encode('utf8'))
                if size>MAX_BODY_BYTES: raise Truncated('body bytes budget')
                if total+size>MAX_TOTAL_BODY_BYTES: raise Truncated('total body bytes budget')
                total+=size
                if headers_truncated:
                    raise Truncated('request header count budget')
                if ctype_oversized:
                    raise Truncated('content type header bytes budget')
                if encodings and any(v!='identity' for v in encodings):
                    fmt,status='opaque','unsupported';reason='HTTP content encoding unsupported'
                elif len(ctypes)>1:
                    fmt,status='unresolved','unsupported';reason='conflicting content type headers'
                else:
                    fields,fmt,status=parse_body(body,ctype)
                if total_fields+len(fields)>MAX_TOTAL_FIELDS:
                    raise Truncated('total decoded fields budget')
                total_fields+=len(fields)
                availability='available' if status=='parsed' else 'unsupported'
            except Truncated as exc:
                availability=status='truncated';reason=str(exc);fields=[]
            except (Malformed,UnicodeError,ValueError,RecursionError):
                availability=status='malformed';reason='request body syntax invalid';fields=[]
        elif source['literal_present'] and body is not None:
            availability=status='unsupported';fmt='binary_or_opaque';reason='literal body representation unsupported'
            preserved=True
        elif isinstance(source['entries'],list) and len(source['entries'])>MAX_PARAMETERS:
            availability=status='truncated';reason='encoded entries count budget'
            preserved=event.payload['state']=='encoded_unresolved'
        elif isinstance(source['entries'],list) and any(isinstance(e,dict) and isinstance(e.get('bytes'),str) and e['bytes'] for e in source['entries']):
            availability=status='unsupported';fmt='binary_or_opaque';reason='encoded artifact entries unsupported without literal postData'
            preserved=True
        counts['available']+=int(preserved)
        counts['unavailable']+=int(not preserved)
        if status in {'unsupported','malformed','truncated'}: counts[status]+=1
        if status=='parsed': counts['parsed']+=1
        if status=='parsed' and fmt=='empty': counts['empty']+=1
        body_ref=registry.add('result','request_payload','runtime_observed' if preserved else 'artifact_unavailable',
                              {'json_pointer':body_pointer if availability!='unavailable' else pointer},
                              'Preserved request-body structure only; source values not compared',
                              details={'body_availability':availability,'parser_status':status})
        refs=list(event.evidence_refs)+[body_ref]
        if ctypes or encodings:
            refs.append(registry.add('result','network_request','runtime_observed',{'json_pointer':pointer+'/headers'},
                                     'Preserved request headers used only for body format; values omitted',details={'media_type':media}))
        multiplicity=Counter(f['path'] for f in fields)
        header_refs=refs[len(event.evidence_refs)+1:]
        for i,f in enumerate(fields):
            field_ref=registry.add('result','request_payload','runtime_observed',
                {'json_pointer':body_pointer,'body_field_path':f['path'],'field_index':i},
                'Runtime body field structure preserved; value omitted',
                details={'value_type':f['value_type'],'semantic_role':f['semantic_role'],'semantic_basis':'field_name_only'})
            f.update(id=registry.identifier('runtime-field',[event.pointer,f['path'],i]),
                     index=i,multiplicity=multiplicity[f['path']],evidence_refs=[body_ref,field_ref]+header_refs)
            refs.append(field_ref)
        record={'id':registry.identifier('runtime-payload',[event.pointer]),'request_ref':event.pointer,
                'body_availability':availability,'body_format':fmt,'media_type':media,'parser_status':status,
                'fields':fields,'truncation':{'truncated':status=='truncated','reason':reason if status=='truncated' else None},
                'reason':reason,'evidence_refs':list(dict.fromkeys(refs)),
                'source_relationship':'unresolved','value_relationship':'unresolved'}
        output.runtime_payloads.append(record)
    details={'requests_inspected':len(events),'bodies_available':counts['available'],
             'bodies_unavailable':counts['unavailable'],'parsed':counts['parsed'],
             'unsupported':counts['unsupported'],'malformed':counts['malformed'],'truncated':counts['truncated'],
             'empty':counts['empty'],
             'budgets':{'body_bytes':MAX_BODY_BYTES,'total_body_bytes':MAX_TOTAL_BODY_BYTES,'fields':MAX_FIELDS,
                        'total_fields':MAX_TOTAL_FIELDS,'depth':MAX_DEPTH,'array_items':MAX_ARRAY_ITEMS,'name_chars':MAX_NAME_CHARS,
                        'multipart_parts':MAX_PARTS,'parameters':MAX_PARAMETERS},
             'values':'omitted','value_comparison':'not_performed'}
    requests=output.evidence_coverage['requests']
    available=(requests.availability if output.network_requests is None else
               'available' if counts['available'] or requests.count==0 else 'unavailable')
    output.evidence_coverage['request_bodies']=EvidenceCoverage(available,
        'not_run' if output.network_requests is None else 'partial' if any(counts[k] for k in ('unavailable','unsupported','malformed','truncated')) or output.evidence_coverage['requests'].inspection!='complete' else 'complete',
        None if output.network_requests is None else counts['available'],
        reason='Body not preserved does not establish an empty body; only bounded structure inspected',details=details)
