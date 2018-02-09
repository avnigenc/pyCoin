#-*- coding: utf-8 -*-
import json, time, collections
from django.shortcuts import *
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from pycoin.myrsa import *
from django.db.models import Sum
import base64, hashlib
from core.models import transaction
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def landing(request):
    try:
        pubkey = request.session['pubkey'].encode('utf-8')
        prikey = request.session['prikey'].encode('utf-8')
        wallet_id = hashlib.sha256(pubkey).hexdigest()
        balance = getbalance(wallet_id)
        if balance is None:
            balance = 0
        return render(request, "ok.html", locals())
    except KeyError:
        return render(request, "index.html", locals())

def getbalance(wallet_id):
    outgoing = transaction.objects.filter(senderhexdigest=wallet_id).aggregate(Sum('amount'))['amount__sum']
    income = transaction.objects.filter(receiverhexdigest=wallet_id).aggregate(Sum('amount'))['amount__sum']
    # print(outgoing)
    # print(income)

    if income and outgoing:
        # print("user have both")
        return(income - outgoing)
    elif outgoing is None:
        # print("user dont have  outgoing")
        return income
    elif income is None:
        return 0
    else:
        return 0

def login(request):
    try:
        pubkey = request.session['pubkey']
        prikey = request.session['prikey']
        return HttpResponseRedirect('/')
    except KeyError:
        return render(request, "login.html", locals())

def logout(request):
    request.session.clear()
    return HttpResponseRedirect('/')

# @author "Hüseyin Terkir"
def createnewwallet(request):
    data = {}
    my_key = RSA.generate(1024)
    public_key = my_key.publickey().exportKey('PEM')
    private_key = my_key.exportKey('PEM')
    wallet_id = hashlib.sha256(public_key).hexdigest()
    data["public_key"] = base64.b64encode(public_key).decode('utf-8')
    data["private_key"] = base64.b64encode(private_key).decode('utf-8')
    data["wallet_id"] = wallet_id

    print(public_key)
    print("---------------")
    print(private_key)
    print("---------------")
    print(wallet_id)

    return render(request, 'wallet.html', {'walletinfo': data})

def miner(first_timestamp, senderwalletid, receiverhex, amount):
    data = {}
    for nonce in range(0,10000000):
        data['senderpublickey'] = str(senderwalletid)
        data['receiverhex'] = str(receiverhex)
        data['previous_hash'] =  str(transaction.objects.all().last().blockhash)
        data['amount'] = str(amount) #4
        data['timestamp'] =  str(first_timestamp)
        data["nonce"] = str(nonce)
        data = collections.OrderedDict(sorted(data.items()))
        datashash  = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
        last2char = datashash[-2:]
        if last2char == "01":
            return(nonce)
        else:
            continue


@csrf_exempt
def checkwallet(request):
    data = {}
    pubkey = request.POST.get('pubkey').strip()
    prikey = request.POST.get('prikey').strip()    
    mypubkey = base64.b64decode(pubkey)
    myprikey = base64.b64decode(prikey)
        
    try:
        mykey = RSA.importKey(myprikey.decode('utf-8')) 
    except UnicodeDecodeError:
        data["response"] = "Check your wallet details UnicodeDecodeError"
        return HttpResponse(json.dumps(data), content_type = "application/json")
    except TypeError:
        data["response"] = "Check your wallet details"
        return HttpResponse(json.dumps(data), content_type = "application/json")
    except ValueError:
        data["response"] = "Check your wallet details ValueError"
        return HttpResponse(json.dumps(data), content_type = "application/json")
    

    example_text = "pycoin".encode('utf-8')
    cipher = PKCS1_v1_5.new(mykey)
    myencdata = mykey.encrypt(example_text, cipher)
    mydedeceddata = mykey.decrypt(myencdata)

    
    if mydedeceddata == example_text:
        request.session['pubkey'] = base64.b64decode(pubkey).decode('utf-8')
        request.session['prikey'] = base64.b64decode(prikey).decode('utf-8')
        data["response"] = "access_approved"
        return HttpResponse(json.dumps(data), content_type = "application/json")
    
    else:
        data["response"] = "access_denied"
        return HttpResponse(json.dumps(data), content_type = "application/json")

    print(mypubkey)
    print(myprikey)
    data["response"] = "ok"
    return HttpResponse(json.dumps(data), content_type="application/json")

@csrf_exempt
def sendpycoin(request):
    allify = {}
    data = {}
    if request.method == 'POST':
        senderpubkey = request.POST.get('spubkey')
        senderprivatekey = request.POST.get('sprikey').strip()
        senderwalletid = request.POST.get('swid')
        receiver = request.POST.get('pubkey').strip()
        receiverhex  = hashlib.sha256(base64.b64decode(receiver)).hexdigest()
        amount = request.POST.get('amount').strip()

        if int(amount) <= 0:
            allify['response'] = "fail"
            return HttpResponse(json.dumps(allify), content_type = "application/json")

        balance = getbalance(senderwalletid)
        if balance is None:
            balance = 0
        if int(amount) > int(balance):
            allify['response'] = "fail"
            return HttpResponse(json.dumps(allify), content_type = "application/json")
        else:
            first_timestamp = time.time()
            data['senderpublickey'] = str(senderwalletid) #1
            data['receiverhex'] = str(receiverhex)      #2
            data['previous_hash'] = str(transaction.objects.all().last().blockhash) #3
            data['amount'] = str(amount) #4
            data['timestamp'] = str(first_timestamp) #5
            perfect =  miner(first_timestamp, senderwalletid, receiverhex, amount)
            data["nonce"] = str(perfect)
            data = collections.OrderedDict(sorted(data.items()))

            datashash  = hashlib.sha256(json.dumps(data).encode('utf-8')).hexdigest()
            
            #senderprivatekeyde = base64.b64decode(senderprivatekey)
            #rsakey = RSA.importKey(senderprivatekeyde)                 
            #digitalSignature = rsakey.sign(datashash.encode('utf-8'),'')
            #digitalSignature = json.dumps(digitalSignature)

            newtrans = transaction(sender=base64.b64encode(senderpubkey.encode('utf-8')),
            senderhexdigest=senderwalletid,
            receiver=receiver,
            receiverhexdigest=receiverhex,
            prevblockhash=transaction.objects.all().last().blockhash,
            blockhash=datashash,
            amount=amount,
            nonce=perfect,
            first_timestamp=first_timestamp,
            #P2PKH=digitalSignature,
            verification=True
            )
            newtrans.save()

            return render(request, 'ok.html', locals())



def ws(request):

    transactions = transaction.objects.all()[::-1][0:8]
    return render(request, "ws.html", locals())

def gettransaction(request, tid):
        data = {}
        trr = transaction.objects.get(id=int(tid))
        data = {"sender" : trr.sender,
                     "senderhexdigest": trr.senderhexdigest,
                     "receiver": trr.receiver,
                     "receiverhexdigest": trr.receiverhexdigest,
                     "prevblockhash": trr.prevblockhash,
                     "blockhash": trr.blockhash,
                     "amount": trr.amount,
                     "nonce": trr.nonce,
                     "first_timestamp": trr.first_timestamp,
                     "saved_timestamp": trr.saved_timestamp.strftime("%Y-%m-%d"),
                     "P2PKH": trr.P2PKH,
                     "verification": trr.verification}
        return HttpResponse(json.dumps(data), content_type = "application/json")




def alltransactions(request):
    data = {}
    txs = []
    transactions = transaction.objects.all()
    for trr in transactions:
        gettrs = {"sender" : trr.sender,
                     "senderhexdigest": trr.senderhexdigest,
                     "receiver": trr.receiver,
                     "receiverhexdigest": trr.receiverhexdigest,
                     "prevblockhash": trr.prevblockhash,
                     "blockhash": trr.blockhash,
                     "amount": trr.amount,
                     "nonce": trr.nonce,
                     "first_timestamp": trr.first_timestamp,
                     "saved_timestamp": trr.saved_timestamp.strftime("%Y-%m-%d"),
                     "P2PKH": trr.P2PKH,
                     "verification": trr.verification,
                     "id":trr.id}
        txs.append(gettrs)


        return render(request, 'ws.html', {'transactioninfo': data['alltestsarecomplated']})
