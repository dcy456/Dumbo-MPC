import logging
import asyncio
from pickle import dumps, loads
from beaver.symmetric_crypto import SymmetricCrypto
from beaver.broadcast.reliablebroadcast import reliablebroadcast
from beaver.broadcast.avid import AVID
from beaver.utils.misc import wrap_send, subscribe_recv
import time
from ctypes import *
import json, gc

lib = CDLL("./pedersen_out.so")

lib.pyPedCommit.argtypes = [c_char_p, c_char_p, c_int]
lib.pyPedCommit.restype = c_char_p

lib.pyPedKeyEphemeralGen.argtypes = [c_char_p, c_char_p]
lib.pyPedKeyEphemeralGen.restype = c_char_p

lib.pyPedSharedKeysGen_sender.argtypes = [c_char_p, c_char_p, c_int]
lib.pyPedSharedKeysGen_sender.restype = c_char_p

lib.pyPedSharedKeysGen_recv.argtypes = [c_char_p, c_char_p]
lib.pyPedSharedKeysGen_recv.restype = c_char_p

lib.pyPedVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyPedVerify.restype = c_bool

lib.pyPedParseRandom_Commit.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyPedParseRandom_Commit.restype = c_char_p

lib.pyPedprodverify.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyPedprodverify.restype = c_bool

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


class HbAVSSMessageType:
    OK = "OK"
    IMPLICATE = "IMPLICATE"
    READY = "READY"
    RECOVERY = "RECOVERY"
    RECOVERY1 = "RECOVERY1"
    RECOVERY2 = "RECOVERY2"
    KDIBROADCAST = "KDIBROADCAST"

class Hbacss0:
    #@profile
    def __init__(
            self, public_keys, private_key, crs, n, t, my_id, send, recv, msgmode):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.my_id = n, t, my_id
        #todo: g should be baked into the pki or something
        self.srs = crs
        # deserialized_srs_kzg = json.loads(crs.decode('utf-8'))
        # self.srs_pk = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
        
        self.mode = msgmode

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        self.avid_msg_queue = asyncio.Queue()
        self.tasks = []
        self.shares_future = asyncio.Future()
        self.output_queue = asyncio.Queue(maxsize=self.n)
        self.tagvars = {}

    async def _recv_loop(self, q):           
        avid, tag, dispersal_msg_list = await q.get()
        await avid.disperse(tag, self.my_id, dispersal_msg_list)
        
    def __enter__(self):
        # self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
                

    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        # self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        # self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable brosrs_kzgadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.my_id)

        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(dealer_id, tag, dispersal_msg, rbc_msg)
        
        if self.tagvars[tag]['all_shares_valid']:
            if self.mode == "avss_without_proof":
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
                self.tagvars[tag]['proofsandshares'] = None
                self.tagvars[tag]['commitments'] = None
                avid = None
                dispersal_msg = None
                rbc_msg = None
                del dispersal_msg, rbc_msg, avid, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']
                gc.collect
            if self.mode == "avss_with_proof":
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
                self.tagvars[tag]['proofsandshares'] = None
                self.tagvars[tag]['commitments'] = None
                avid = None
                dispersal_msg = None
                rbc_msg = None
                del dispersal_msg, rbc_msg, avid, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']
                gc.collect

            output = True
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

        # obtain
        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()
            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break

    #@profile
    def _get_dealer_msg(self, acsstag, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        
        shares = []
        if self.mode == "avss_without_proof":
            commandproof = lib.pyPedCommit(self.srs, values, self.t)
            deserialized_commandproof = json.loads(commandproof.decode('utf-8'))
            serialized_commitment = json.dumps(deserialized_commandproof['com']).encode('utf-8')
            for i in range(self.n):
                # serialized_proofandshares = json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8')
                shares.append(json.dumps(deserialized_commandproof["eval"][i]).encode('utf-8'))
        if self.mode == "avss_with_proof":
            # serialized_com_proof = values
            deserialized_commandprooflist = json.loads(values.decode('utf-8'))
            
            # commitmentlist = deserialized_commandprooflist['commitment']
            # prooflist = deserialized_commandprooflist["proof"]
            
            serialized_commitmentlist = json.dumps(deserialized_commandprooflist['commitment']).encode('utf-8')
            serialized_sharelist = json.dumps(deserialized_commandprooflist["share"]).encode('utf-8')
            commitmentlistandprooflist = lib.pyPedParseRandom_Commit(self.srs, serialized_commitmentlist, serialized_sharelist, self.t, self.my_id)
            deser_comsandproofs = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deser_comsandproofs['com_c']).encode('utf-8') 
            serialized_T_ab = json.dumps(deser_comsandproofs['T_ab']).encode('utf-8') 
            serialized_T_c = json.dumps(deser_comsandproofs['T_c']).encode('utf-8') 
            serialized_prodProofs = json.dumps(deser_comsandproofs['prodproof']).encode('utf-8')
            serialized_proof_ab = json.dumps(deser_comsandproofs['proof_ab']).encode('utf-8')
            serialized_proof_c = json.dumps(deser_comsandproofs['proof_c']).encode('utf-8') 
            
            for i in range(self.n):
                # serialized_proofandshares = json.dumps(deser_comsandproofs['proofs_c'][i]).encode('utf-8')
                shares.append(json.dumps(deser_comsandproofs['eval_c'][i]).encode('utf-8'))       
        
        # for i in range(self.n):
        #     lib.pyPedVerify(self.srs, serialized_commitment, shares[i], i, self.t)
        serialized_ephemeralpublicsecretkey = lib.pyPedKeyEphemeralGen(self.srs, self.public_keys)
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')

        dispersal_msg_list = [None] * n
        shared_keys = [None] * n
        for i in range(n):
            shared_keys[i] = lib.pyPedSharedKeysGen_sender(self.public_keys, serialized_ephemeralsecretkey, i)
            if self.mode == "avss_without_proof":
                z = shares[i]
            if self.mode == "avss_with_proof":
                z = (shares[i], serialized_T_ab, serialized_T_c, serialized_prodProofs, serialized_proof_ab, serialized_proof_c)
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), z)
        return dumps((serialized_commitment, serialized_ephemeralpublickey)), dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, dealer_id, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        
        serialized_commitment, serialized_ephemeral_public_key = loads(rbc_msg)
        serialized_sharedkey =  lib.pyPedSharedKeysGen_recv(serialized_ephemeral_public_key, self.private_key)

        # self.tagvars[tag]['shared_key'] = serialized_sharedkey
        # self.tagvars[tag]['ephemeral_public_key'] = serialized_ephemeral_public_key
        try:
            if self.mode == "avss_without_proof":
                serialized_shares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_proof":
                serialized_shares, serialized_T_ab, serialized_T_c, serialized_prodProofs, serialized_proof_ab, serialized_proof_c = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
                
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
         
        
        if all_shares_valid:
            if self.mode == "avss_without_proof":
                if lib.pyPedVerify(self.srs, serialized_commitment, serialized_shares, self.my_id, self.t) == int(1):
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_shares
                    serialized_commitment = None
                    serialized_shares = None
                    del serialized_commitment, serialized_shares
                    gc.collect
                else:
                    all_shares_valid = False
            if self.mode == "avss_with_proof":
                if lib.pyPedVerify(self.srs, serialized_commitment, 
                serialized_shares, self.my_id, self.t) == int(1) and lib.pyPedprodverify(
                    self.srs, serialized_commitment, self.tagvars[tag]['committment_ab'], 
                    serialized_T_ab, serialized_T_c, serialized_prodProofs, 
                    serialized_proof_ab, serialized_proof_c, dealer_id, self.t
                    ) == int(1):
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_shares
                        serialized_commitment = None
                        self.tagvars[tag]['committment_ab'] = None
                        serialized_T_ab = None
                        serialized_T_c = None 
                        serialized_prodProofs = None 
                        serialized_proof_ab = None
                        serialized_proof_c = None
                        del serialized_commitment, self.tagvars[tag]['committment_ab'], serialized_T_ab, serialized_T_c, serialized_prodProofs, serialized_proof_ab, serialized_proof_c
                        gc.collect

                else:
                    return False
                
    
        return all_shares_valid

    #@profile
    async def avss(self, avss_id, coms=None, values=None, dealer_id=None, client_mode=False):
        """
        A batched version of avss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        if client_mode:
            assert dealer_id is not None
            assert dealer_id == self.n
        assert type(avss_id) is int

        logger.debug(
            "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d, Client Mode: %s",
            self.my_id,
            avss_id,
            dealer_id,
            client_mode,
        )
        
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"
        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []
        if self.mode == "avss_with_proof":
            self.tagvars[acsstag]['committment_ab'] = coms
            

        # In the client_mode, the dealer is the last node
        n = self.n if not client_mode else self.n + 1
        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(acsstag, values, n)
        
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        rbc_msg = await reliablebroadcast(
            rbctag,
            self.my_id,
            n,
            self.t,
            dealer_id,
            broadcast_msg,
            recv,
            send,
            client_mode=client_mode,
        )  # (# noqa: E501)
        avidtag = f"{dealer_id}-{avss_id}-B-AVID"
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        
        send, recv = self.get_send(avidtag), self.subscribe_recv(avidtag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(n, self.t, dealer_id, recv, send, n)
        # start disperse in the background
        self.avid_msg_queue.put_nowait((avid, avidtag, dispersal_msg_list))

        broadcast_msg = None
        dispersal_msg_list = None
        del broadcast_msg, dispersal_msg_list
        gc.collect

        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)
        
        # for task in self.tagvars[acsstag]['tasks']:
        #     print(task)
        #     task.cancel()
        # self.tagvars[acsstag] = {}
        # del self.tagvars[acsstag]
        
        


class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        if not self.tagvars[tag]['in_share_recovery']:
            return
        ls = len(self.tagvars[tag]['commitments']) // (self.t + 1)
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['finished_interpolating_commits']:
            all_commits = [ [] for l in range(ls)]
            for l in range(ls):
                known_commits = self.tagvars[tag]['commitments'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
                # line 502
                interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
                #interpolated_commits = known_commits + known_commits + known_commits
                all_commits[l] = known_commits + interpolated_commits
            self.tagvars[tag]['all_commits'] = all_commits
            self.tagvars[tag]['finished_interpolating_commits'] = True

            #init some variables we'll need later
            self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r1_aux_coords_l'] = [[] for l in range(ls)]
            self.tagvars[tag]['r2_aux_coords_l'] = [[] for l in range(ls)]
            self.tagvars[tag]['sent_r2'] = False
            self.tagvars[tag]['r1_set'] = set()
            self.tagvars[tag]['r2_set'] = set()
            
            if self.tagvars[tag]['all_shares_valid']:
                logger.debug("[%d] prev sent r1", self.my_id)
                all_evalproofs = [ [] for l in range(ls)]
                all_points = [ [] for l in range(ls)]
                all_aux_points = [[] for l in range(ls)]
                for l in range(ls):
                    # the proofs for the specific shares held by this node
                    known_evalproofs = self.tagvars[tag]['witnesses'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
                    # line 504
                    interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                                            range(self.t + 1, self.n)]
                    #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
                    all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
                    # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
                    known_points = self.tagvars[tag]['shares'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
                    mypoly = self.poly.interpolate(known_point_coords)
                    interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
                    all_points[l] = known_points + interpolated_points

                    #auxes
                    known_auxes = self.tagvars[tag]['auxes'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_aux_coords = [[i + 1, known_auxes[i]] for i in range(self.t + 1)]
                    my_aux_poly = self.poly.interpolate(known_aux_coords)
                    interpolated_aux_points = [my_aux_poly(i + 1) for i in range(self.t + 1, self.n)]
                    all_aux_points[l] = known_auxes + interpolated_aux_points


                logger.debug("[%d] in between r1", self.my_id)
                # lines 505-506
                for j in range(self.n):
                    send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)] , [ all_aux_points[l][j] for l in range(ls)], [all_evalproofs[l][j] for l in range(ls)]))
                logger.debug("[%d] sent r1", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
            logger.debug("[%d] prev sent r2", self.my_id)
            _, points, aux_points, proofs = avss_msg
            all_commits = self.tagvars[tag]['all_commits']
            if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, aux_points, proofs):
                if sender not in self.tagvars[tag]['r1_set']:
                    self.tagvars[tag]['r1_set'].add(sender)
                    for l in range(ls):
                        self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
                        self.tagvars[tag]['r1_aux_coords_l'][l].append([sender, aux_points[l]])
                    #r1_coords.append([sender, point])
                if len(self.tagvars[tag]['r1_set']) == self.t + 1:
                    #r1_poly = self.poly.interpolate(r1_coords)
                    r1_poly_l = [ [] for l in range(ls)]
                    r1_aux_poly_l = [[] for l in range(ls)]
                    for l in range(ls):
                        r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
                        r1_aux_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_aux_coords_l'][l])
                    for j in range(self.n):
                        r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
                        r1_aux_points_j = [r1_aux_poly_l[l](j) for l in range(ls)]
                        #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
                        send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j, r1_aux_points_j))
                    self.tagvars[tag]['sent_r2'] = True
                    logger.debug("[%d] sent r2", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
            _, points, aux_points = avss_msg
            if sender not in self.tagvars[tag]['r2_set']:
                self.tagvars[tag]['r2_set'].add(sender)
                #r2_coords.append([sender, point])
                for l in range(ls):
                    self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
                    self.tagvars[tag]['r2_aux_coords_l'][l].append([sender, aux_points[l]])
            if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
                # todo, replace with robust interpolate that takes at least 2t+1 values
                # this will still interpolate the correct degree t polynomial if all points are correct
                r2_poly_l = [ [] for l in range(ls)]
                r2_aux_poly_l = [[] for l in range(ls)]
                shares = []
                auxes = []
                for l in range(ls):
                    r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
                    shares += [r2_poly(i) for i in range(self.t + 1)]
                    r2_aux_poly = self.poly.interpolate(self.tagvars[tag]['r2_aux_coords_l'][l])
                    auxes += [r2_aux_poly(i) for i in range(self.t + 1)]
                multicast((HbAVSSMessageType.OK, ""))

                self.tagvars[tag]['all_shares_valid'] = True
                self.tagvars[tag]['shares'] = shares
                self.tagvars[tag]['auxes'] = auxes