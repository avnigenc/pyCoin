#-*- coding: utf-8 -*-
import json, time, collections
from django.shortcuts import *
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from pycoin.myrsa import *
from django.db.models import Sum
import base64, websocket, hashlib
from core.models import transaction

def landing(request):
    try:
        pubkey = request.session['pubkey'].encode('utf-8')
        prikey = request.session['prikey'].encode('utf-8')
        wallet_id = SHA256.new(pubkey).hexdigest()
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
    wallet_id = SHA256.new(public_key).hexdigest()
    data["public_key"] = base64.b64encode(public_key).decode('utf-8')
    data["private_key"] = base64.b64encode(private_key).decode('utf-8')
    data["wallet_id"] = wallet_id

    print(public_key)
    print("---------------")
    print(private_key)
    print("---------------")
    print(wallet_id)

    return render(request, 'wallet.html', {'walletinfo': data})

def miner(first_timestamp, senderwalletid, receiverhex,amount):
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
    if request.method == 'POST':
        pubkey = request.POST.get('pubkey').strip()
        prikey = request.POST.get('prikey').strip()
        # print(pubkey)
        try:
            key = RSA.importKey(base64.b64decode(pubkey))
            public_key = key.publickey()
            enc_data = public_key.encrypt('pycoin'.encode('utf-8'), 32)
            pass_hex = base64.b64encode(enc_data[0])
            enc_data = base64.b64decode(pass_hex)
            newkey =  RSA.importKey(base64.b64decode(prikey))
            x = newkey.decrypt(enc_data)
        except UnicodeDecodeError:
            data["response"] = "Check your wallet details UnicodeDecodeError"
            return HttpResponse(json.dumps(data), content_type = "application/json")
        except TypeError:
            data["response"] = "Check your wallet details"
            return HttpResponse(json.dumps(data), content_type = "application/json")
        except ValueError:
            data["response"] = "Check your wallet details ValueError"
            return HttpResponse(json.dumps(data), content_type = "application/json")
        if x == "pycoin".encode('utf-8'):
            request.session['pubkey'] = base64.b64decode(pubkey).decode('utf-8')
            request.session['prikey'] = base64.b64decode(prikey).decode('utf-8')
            data["response"] = "access_approved"
            return HttpResponse(json.dumps(data), content_type = "application/json")
        else:
            data["response"] = "access_denied"
            return HttpResponse(json.dumps(data), content_type = "application/json")
    else:
        data["response"] = "ONLY POST"
        return HttpResponse(json.dumps(data), content_type = "application/json")
