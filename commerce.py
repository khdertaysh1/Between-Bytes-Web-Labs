"""Stateful local checkout domain: orders, immutable transaction records and fulfilment.

Money uses integer minor units. Provider receipts are seeded local records; no
payment processor is contacted. Gift double spend uses a deterministic schedule.
"""
from collections import deque
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import secrets

PROVIDER_KEY=b'between-bytes-local-provider-key-not-for-production'
PROVIDER_EVENT={'event':'settled','order_id':'order100','amount_minor':10000,'currency':'USD'}

def provider_signature(event='settled'):
    payload={**PROVIDER_EVENT,'event':event}
    return hmac.new(PROVIDER_KEY,json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()


def checkout_state(state, kind):
    if 'checkout' not in state:
        paid=kind=='refund'
        state['checkout']={
            'order':{'id':'order100','customer_id':'cus_alice','status':'paid' if paid else 'awaiting_payment',
                     'currency':'USD','items':[{'sku':'SEC-KIT' if kind=='shipping' else 'SEC-COURSE','name':'Security Workshop Kit' if kind=='shipping' else 'Web Security Course','quantity':1,'unit_amount':10000}],
                     'totals':{'subtotal':10000,'shipping':1000 if kind=='shipping' else 0,'tax':1000 if kind=='tax' else 0,'discount':0,'amount_due':11000 if kind in {'shipping','tax'} else 10000},
                     'captured_amount':10000 if paid else 0,'refunded_amount':0,'revision':0},
            'transactions':deque(maxlen=80),'entitlements':0,'gift_balance':10000,
            'coupon_redemptions':0,'processed_events':set(),'trial_consumed':True,
            'subscriptions':deque(maxlen=20),
            'provider_receipts':{'settled-order100':{'id':'pi_main','order_id':'order100','status':'settled','amount':10000,'currency':'USD'},
                                 'settled-order1':{'id':'pi_small','order_id':'order1','status':'settled','amount':100,'currency':'USD'},
                                 'pending-order100':{'id':'pi_pending','order_id':'order100','status':'pending','amount':0,'currency':'USD'}}}
    return state['checkout']


def snapshot(state,kind):
    c=checkout_state(state,kind)
    return {'order':deepcopy(c['order']),'transactions':list(c['transactions']),
            'entitlements':{'downloads':c['entitlements']},'gift_card':{'id':'gift_alice','balance':c['gift_balance'],'currency':'USD'},
            'coupon':{'code':'WELCOME','redemptions':c['coupon_redemptions'],'per_customer_limit':1},
            'subscriptions':list(c['subscriptions'])}


def execute(kind,fixed,d,state,integer,text):
    c=checkout_state(state,kind);order=c['order'];r={'status':200,'impact':False,'protected':False,'legitimate':False}
    def change(event,amount=0,**extra):
        order['revision']+=1
        c['transactions'].append({'id':'txn_'+secrets.token_hex(5),'sequence':order['revision'],'type':event,'amount':amount,'currency':order['currency'],**extra})
    def paid(receipt,unverified=False):
        # Re-entering the same normal settlement is idempotent in both variants.
        identity=receipt['id'] if receipt else 'unverified-client-status'
        order['status']='paid'
        if identity not in c['processed_events']:
            c['processed_events'].add(identity)
            amount=receipt['amount'] if receipt else 0
            order['captured_amount']+=amount;c['entitlements']+=1
            change('fulfilment_released',amount,provider_payment=identity,provider_order=receipt['order_id'] if receipt else None,provider_currency=receipt['currency'] if receipt else None,verified=not unverified)
    def finish(bad=False,**fields):
        r.update(impact=bad and not fixed,protected=bad and fixed,legitimate=not bad and fixed,**fields)
        return r
    if kind in {'price','total','shipping','tax','discount','quantity','rounding'}:
        expected={'price':10000,'total':10000,'shipping':1000,'tax':1000,'discount':0,'quantity':1}
        if kind=='rounding':
            try:
                value=Decimal(text(d,'amount','100.00'))
                if not value.is_finite() or abs(value)>1000000:raise ValueError('Invalid amount')
                submitted=int(value*100)
            except InvalidOperation:raise ValueError('Invalid amount')
            bad=value!=Decimal('100.00')
            if fixed and bad:return finish(True,status=422,amount_due_minor=order['totals']['amount_due'],catalog_unit_minor=10000,currency='USD')
            due=10000 if fixed else submitted
        else:
            value=integer(d,kind,expected[kind]);trusted=11000 if kind in {'shipping','tax'} else 10000
            if kind=='quantity':
                bad=not 1<=value<=10
                if fixed and bad:return finish(True,status=422,amount_due_minor=order['totals']['amount_due'],catalog_unit_minor=10000)
                order['items'][0]['quantity']=value;due=10000*value
            elif kind=='discount':bad=value!=0;due=10000 if fixed else 10000*(100-value)//100
            elif kind in {'shipping','tax'}:bad=value!=1000;due=trusted if fixed else 10000+value
            else:bad=value!=trusted;due=trusted if fixed else value
            if fixed and bad:return finish(True,status=422,amount_due_minor=order['totals']['amount_due'],catalog_unit_minor=10000,currency='USD')
            if kind=='price':order['items'][0]['unit_amount']=10000 if fixed else value
        totals=order['totals']
        if kind=='shipping':totals['shipping']=1000 if fixed else value
        elif kind=='tax':totals['tax']=1000 if fixed else value
        elif kind=='discount':totals['discount']=0 if fixed else 10000-due
        elif kind=='quantity':totals['subtotal']=10000*value
        elif kind=='price':totals['subtotal']=order['items'][0]['unit_amount']*order['items'][0]['quantity']
        totals['amount_due']=due;change('quote_updated',due)
        return finish(bad,amount_due_minor=due,catalog_unit_minor=10000,currency='USD')
    if kind=='currency':
        currency=text(d,'currency','USD')
        if currency not in {'USD','JPY','EUR'}:raise ValueError('Choose USD, EUR or JPY')
        bad=currency!=order['currency']
        if fixed and bad:return finish(True,status=409,order_currency='USD',interpreted_currency='USD',amount_minor=10000)
        receipt={'id':'pi_currency_'+currency,'amount':10000,'currency':currency,'status':'settled','order_id':'order100'}
        paid(receipt,unverified=bad)
        return finish(bad,order_currency='USD',interpreted_currency=currency,amount_minor=10000)
    if kind=='coupon-reuse':
        if text(d,'coupon','WELCOME')!='WELCOME':raise ValueError('Unknown coupon')
        count=integer(d,'repeat',1,1,8);applied=0;operations=[]
        for _ in range(count):
            if fixed and c['coupon_redemptions']>=1:
                operations.append({'status':409,'code':'coupon_already_redeemed'});continue
            operations.append({'status':200,'code':'coupon_redeemed'})
            c['coupon_redemptions']+=1;applied+=1
            order['totals']['discount']=c['coupon_redemptions']*2000
            order['totals']['amount_due']=10000-order['totals']['discount'];change('coupon_redeemed',2000,code='WELCOME')
        state['used']=c['coupon_redemptions']
        return {**r,'status':409 if fixed and applied==0 else 207 if fixed and applied<count else 200,'operations':operations,'impact':not fixed and c['coupon_redemptions']>1,'protected':fixed and applied<count,'legitimate':fixed and count==1 and applied==1,
                'applications_total':c['coupon_redemptions'],'applied_this_run':applied,'entitlement':'discount'}
    if kind in {'status','binding','webhook'}:
        if kind=='webhook':
            event=text(d,'event','pending');signature=text(d,'signature')
            verified=hmac.compare_digest(signature,provider_signature(event))
            bad=event=='settled' and not verified
            if fixed and not verified:return finish(True,status=401,signature_verified=False,order_state=order['status'])
            receipt=c['provider_receipts']['settled-order100'] if verified else None
            if event=='settled':paid(receipt,unverified=not verified)
            return finish(bad,signature_verified=verified,order_state=order['status'],source='HMAC-SHA256 over canonical seeded event')
        key=text(d,'receipt','pending-order100') if kind=='status' else text(d,'payment','settled-order100')
        receipt=c['provider_receipts'].get(key)
        if not receipt:raise ValueError('Unknown provider receipt')
        if kind=='status':
            claim=text(d,'status','pending')
            if claim not in {'pending','paid'}:raise ValueError('Choose pending or paid')
            settled=receipt['status']=='settled';bad=claim=='paid' and not settled
            if not fixed and claim=='paid':paid(receipt if settled else None,unverified=not settled)
            elif fixed and settled:paid(receipt)
            if fixed and bad:r['status']=409
            return finish(bad,provider_ledger=receipt['status'],order_state=order['status'])
        bad=receipt['order_id']!=order['id'] or receipt['amount']!=order['totals']['amount_due'] or receipt['currency']!=order['currency']
        if fixed and bad:r['status']=409
        else:paid(receipt,unverified=bad)
        return finish(bad,order_id=order['id'],order_due_minor=order['totals']['amount_due'],payment_order=receipt['order_id'],payment_minor=receipt['amount'],order_state=order['status'])
    if kind=='replay':
        event=text(d,'event_id','evt-demo')
        if event!='evt-demo':raise ValueError('Use the seeded event')
        count=integer(d,'repeat',1,1,8);applied=0
        for _ in range(count):
            if fixed and event in c['processed_events']:continue
            c['processed_events'].add(event);c['entitlements']+=1;applied+=1;change('entitlement_granted',0,event_id=event)
        state['used']=c['entitlements']
        return {**r,'impact':not fixed and c['entitlements']>1,'protected':fixed and applied<count,'legitimate':fixed and count==1 and applied==1,
                'applications_total':c['entitlements'],'applied_this_run':applied,'entitlement':'download credit','idempotent_replay':applied<count}
    if kind=='gift':
        amount=integer(d,'spend',6000,1,10000);count=integer(d,'repeat',1,1,8);before=c['gift_balance'];accepted=0;operations=[]
        for worker in range(count):
            available=c['gift_balance'] if fixed else before
            if available<amount:
                operations.append({'status':409,'code':'insufficient_credit'});continue
            operations.append({'status':200,'code':'gift_debited'})
            c['gift_balance']-=amount;accepted+=1;change('gift_debited',amount,worker=worker+1)
        state['balance']=c['gift_balance']
        return {**r,'status':409 if accepted==0 else 207 if accepted<count else 200,'operations':operations,'impact':not fixed and c['gift_balance']<0,'protected':fixed and accepted<count,'legitimate':fixed and count==1 and accepted==1,
                'balance_minor':c['gift_balance'],'redemptions_this_run':accepted,'schedule':'deterministic stale-read interleaving; not a live race'}
    if kind=='refund':
        amount=integer(d,'refund',1000,1,1000000);bad=order['refunded_amount']+amount>order['captured_amount']
        accepted=not(fixed and bad)
        if accepted:order['refunded_amount']+=amount;change('refund_created',amount)
        else:r['status']=409
        state['refunded']=order['refunded_amount']
        return finish(bad,captured_minor=order['captured_amount'],refunded_minor=order['refunded_amount'],accepted=accepted)
    if kind=='trial':
        plan=text(d,'plan','basic');purchase=text(d,'purchase','paid')
        if plan not in {'basic','premium'} or purchase not in {'trial','paid'}:raise ValueError('Unknown subscription choice')
        bad=purchase=='trial' and c['trial_consumed']
        if fixed and bad:r['status']=409
        else:
            c['subscriptions'].append({'id':'sub_'+secrets.token_hex(4),'plan':plan,'status':'trialing' if purchase=='trial' else 'active','customer_id':'cus_alice'})
            change('subscription_created',0 if purchase=='trial' else 10000,plan=plan)
        return finish(bad,already_used_on='basic',requested_plan=plan,trial_granted=bad and not fixed,paid_subscription_allowed=purchase=='paid')
    raise ValueError('Unknown checkout operation')
