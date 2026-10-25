"""Business HTTP representations, separate from classroom assessment metadata."""
from copy import deepcopy
from commerce import snapshot

ERRORS={
 'pay-price':('price_mismatch','The unit price does not match the server catalog.'),
 'pay-total':('total_mismatch','The submitted total does not match the server-calculated total.'),
 'pay-discount':('discount_not_authorized','This discount is not authorized for this order.'),
 'pay-shipping':('shipping_mismatch','The shipping fee does not match the selected delivery method.'),
 'pay-tax':('tax_mismatch','The tax does not match the server-calculated tax.'),
 'pay-rounding':('invalid_payment_amount','The amount must exactly match the order in minor units.'),
 'pay-coupon-reuse':('coupon_already_redeemed','This coupon has already been redeemed by this customer.'),
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
        if 'operations' in result:data['operations']=result['operations']
        data['outcome']='rejected' if status>=400 else 'partial' if status==207 else 'duplicate_ignored' if result.get('idempotent_replay') and result.get('applied_this_run')==0 else 'accepted'
        if 'redemptions_this_run' in result:data['redemptions_applied']=result['redemptions_this_run']
        if status>=400:
            code,message=ERRORS.get(case,('operation_rejected','The operation conflicts with the current resource state.'))
            payload={'error':{'code':code,'message':message},'data':{'order':data['order'],'outcome':'rejected',**({'operations':data['operations']} if 'operations' in data else {})}}
        else:payload={'data':data}
        headers['ETag']='"order100-r'+str(data['order']['revision'])+'"'
    elif case.startswith(('upload-', 'traversal-', 'disclosure-', 'authentication-')):
        payload = {'data': deepcopy(result['data'])}
        if status >= 400:
            payload['error'] = {'code': result.get('error_code', 'operation_rejected'), 'message': 'The requested resource or operation is not available under this policy.'}
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
        payload['attempts']={'checked':result['accepted_failed_attempts'],'throttled':result['blocked'],'operations':[{'status':401} for _ in range(result['accepted_failed_attempts'])]+[{'status':429} for _ in range(result['blocked'])]}
    elif case.startswith('xss-'):
        if case=='xss-stored':status=201
        payload={'data':{'preview_url':result['preview'],'source':result['source'],'stored':case=='xss-stored'}}
    elif case.startswith('csrf-'):
        if status>=400:
            code,message=('method_not_allowed','Use POST to change account data.') if status==405 else ('unsupported_content_type','Use the supported form content type.') if status==415 else ('csrf_verification_failed','The request origin or session-bound token could not be verified.')
            if status==405:headers['Allow']='POST'
            payload={'error':{'code':code,'message':message},'data':deepcopy(result['data'])}
        else:payload={'data':deepcopy(result['data'])}
    elif case.startswith('cors-') and status==401:
        payload={'error':{'code':'session_required','message':'A valid session is required.'},'data':deepcopy(result['data'])}
    else:
        if status>=400:
            code,message=('invalid_credentials','Invalid email or password.') if status==401 else ('invalid_request_type','Password must be a string.') if case=='code-nosql' else ('invalid_query','The search query could not be processed.') if case=='code-sqli' else ('destination_not_allowed','The requested operation is not permitted.')
            payload={'error':{'code':code,'message':message}}
        else:payload={'data':{'notes':deepcopy(result['data'])} if case=='code-sqli' else deepcopy(result['data'])}
    payload['request_id']=request_id
    return status,payload,headers
