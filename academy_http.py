"""Business HTTP representations, separate from classroom assessment metadata."""
from copy import deepcopy
from commerce import snapshot

ERRORS={
 'pay-binding':('payment_order_mismatch','The payment cannot settle this order: order, currency and amount must match.'),
 'pay-status':('payment_not_settled','The provider receipt is pending; fulfilment has not been authorized.'),
 'pay-webhook':('invalid_event_signature','The payment event signature could not be verified.'),
 'pay-currency':('currency_mismatch','The payment currency does not match the order currency.'),
 'pay-quantity':('invalid_quantity','Quantity must be an integer between 1 and 10.'),
 'pay-refund':('refund_exceeds_capture','The requested refund exceeds the remaining captured amount.'),
 'pay-trial':('trial_already_used','This customer has already used a trial across the product family.'),
 'pay-gift':('insufficient_credit','The gift card has insufficient remaining credit.'),
}


def response(academy,case,mode,result):
    request_id=result['request_id'];status=result['status'];headers={'X-Request-ID':request_id}
    payload={}
    if case.startswith('pay-'):
        data=snapshot(academy.states[(case,mode)],case[4:])
        if 'idempotent_replay' in result:data['idempotent_replay']=result['idempotent_replay']
        if 'redemptions_this_run' in result:data['redemptions_applied']=result['redemptions_this_run']
        if status>=400:
            code,message=ERRORS.get(case,('operation_rejected','The operation conflicts with the current resource state.'))
            payload={'error':{'code':code,'message':message},'data':{'order':data['order']}}
        else:payload={'data':data}
        headers['ETag']='"order100-r'+str(data['order']['revision'])+'"'
    elif case.startswith('acl-'):
        if status>=400:payload={'error':{'code':'resource_not_found' if status==404 else 'forbidden','message':'Resource not found.' if status==404 else 'Your account does not have permission to perform this operation.'}}
        else:
            key='documents' if case=='acl-batch' else 'document'
            payload={'data':{key:deepcopy(result['data'])}}
    elif case.startswith('rate-'):
        headers.update({'RateLimit-Limit':'3','RateLimit-Remaining':str(result.get('remaining',0))})
        if status==429:headers['Retry-After']='60'
        payload={'error':{'code':'rate_limit_exceeded' if status==429 else 'invalid_credentials','message':'Too many attempts. Try again later.' if status==429 else 'Invalid email or password.'}}
        # A bounded batch summarizes the per-attempt statuses; no credentials are guessed.
        payload['attempts']={'checked':result['accepted_failed_attempts'],'throttled':result['blocked']}
    elif case.startswith('xss-'):
        if case=='xss-stored':status=201
        payload={'data':{'preview_url':result['preview'],'source':result['source'],'stored':case=='xss-stored'}}
    else:
        if status>=400:payload={'error':{'code':'invalid_request_type' if case=='code-nosql' else 'destination_not_allowed','message':'Password must be a string.' if case=='code-nosql' else 'The requested operation is not permitted.'}}
        else:payload={'data':{'notes':deepcopy(result['data'])} if case=='code-sqli' else deepcopy(result['data'])}
    payload['request_id']=request_id
    return status,payload,headers
