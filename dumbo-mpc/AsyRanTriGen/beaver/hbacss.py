import logging
import asyncio
from pickle import dumps, loads
from beaver.symmetric_crypto import SymmetricCrypto
from beaver.broadcast.reliablebroadcast import reliablebroadcast
from beaver.broadcast.avid import AVID
from beaver.utils.misc import wrap_send, subscribe_recv
import time
from ctypes import *
import json

lib = CDLL("./kzg_ped_out.so")

lib.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
lib.pyCommit.restype = c_char_p

lib.pyKeyEphemeralGen.argtypes = [c_char_p]
lib.pyKeyEphemeralGen.restype = c_char_p

lib.pySharedKeysGen_sender.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_sender.restype = c_char_p

lib.pySharedKeysGen_recv.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_recv.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

lib.pyParseRandom.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyParseRandom.restype = c_char_p

lib.pyBatchhiddenverify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchhiddenverify.restype = c_bool

lib.pyBatchhiddenzeroverify.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyBatchhiddenzeroverify.restype = c_bool

lib.pyProdverify.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyProdverify.restype = c_bool

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
        self.srs_kzg = crs
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
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
                
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        # TODO: Add the handle implication
        pass
        # commitments =  self.tagvars[tag]['commitments']
        # # discard if PKj ! = g^SKj
        # if self.public_keys[j] != pow(self.g, j_sk):
        #     return False
        # # decrypt and verify
        # implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, j)
        # j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # # Same as the batch size
        # secret_count = len(commitments)

        # try:
        #     j_shares, j_auxes, j_witnesses = SymmetricCrypto.decrypt(
        #         str(j_shared_key).encode(), implicate_msg
        #     )
        # except Exception as e:  # TODO specific exception
        #     logger.warn("Implicate confirmed, bad encryption:", e)
        #     return True
        # return not self.poly_commit.batch_verify_eval(
        #     commitments, j + 1, j_shares, j_auxes, j_witnesses
        # )



    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
        #     logger.debug("[%d] sent_kdi_broadcast", self.my_id)
        #     kdi = self.tagvars[tag]['shared_key']
        #     multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
        #     self.kdi_broadcast_sent = True
        # if self.tagvars[tag]['all_shares_valid']:
        #     return

        # if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
        #     logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
        #     avid = self.tagvars[tag]['avid']
        #     retrieved_msg = await avid.retrieve(tag, sender)
        #     try:
        #         j_shares, j_witnesses = SymmetricCrypto.decrypt(
        #             str(avss_msg[1]).encode(), retrieved_msg
        #         )
        #     except Exception as e:  # TODO: Add specific exception
        #         logger.debug("Implicate confirmed, bad encryption:", e)
        #     commitments = self.tagvars[tag]['commitments']
        #     if (self.poly_commit.batch_verify_eval(commitments,
        #                                            sender + 1, j_shares, j_witnesses)):
        #         if not self.saved_shares[sender]:
        #             self.saved_shared_actual_length += 1
        #             self.saved_shares[sender] = j_shares

        # # if t+1 in the saved_set, interpolate and sell all OK
        # if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
        #     logger.debug("[%d] interpolating", self.my_id)
        #     # Batch size
        #     shares = []
        #     secret_count = len(self.tagvars[tag]['commitments'])
        #     for i in range(secret_count):
        #         phi_coords = [
        #             (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
        #         ]
        #         shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
        #     self.tagvars[tag]['all_shares_valid'] = True
        #     self.tagvars[tag]['shares'] = shares
        #     self.tagvars[tag]['in_share_recovery'] = False
        #     self.interpolated = True
        #     multicast((HbAVSSMessageType.OK, ""))
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
        # get phi and public key from reliable broadcast msg
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
            if self.mode == "avss_with_proof":
                logging.debug(f"dealer_id: {dealer_id}")
                # serialized_proofsshares = self.tagvars[tag]['proofsandshares']
                # serialized_commitment = self.tagvars[tag]['commitments']
                # self.output_queue.put_nowait((dealer_id, avss_id, serialized_proofsshares, serialized_commitment))
                self.output_queue.put_nowait((dealer_id, avss_id, self.tagvars[tag]['proofsandshares'], self.tagvars[tag]['commitments']))
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
        proofandshares = []
        if self.mode == "avss_without_proof":
            commitmentlistandprooflist = lib.pyCommit(self.srs_kzg['Pk'], values, self.t)
            deserialized_commitmentlistandprooflist = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deserialized_commitmentlistandprooflist['commitmentList']).encode('utf-8')            
            for i in range(self.n):
                proofandshares.append(json.dumps(deserialized_commitmentlistandprooflist["batchproofsofallparties"][i]).encode('utf-8'))
        if self.mode == "avss_with_proof":
            deserialized_commandprooflist = json.loads(values.decode('utf-8'))            
            serialized_commitmentlist = json.dumps(deserialized_commandprooflist['commitment']).encode('utf-8')
            serialized_prooflist = json.dumps(deserialized_commandprooflist['proof']).encode('utf-8')
            commitmentlistandprooflist = lib.pyParseRandom(self.srs_kzg['Pk'], serialized_commitmentlist, serialized_prooflist, self.t, self.my_id)

            deser_comsandproofs = json.loads(commitmentlistandprooflist.decode('utf-8'))
            serialized_commitment = json.dumps(deser_comsandproofs['commitments_c']).encode('utf-8') 
            serialized_zkProof_ab = json.dumps(deser_comsandproofs['zkProof_ab']).encode('utf-8') 
            serialized_zkProof_c_zero = json.dumps(deser_comsandproofs['zkProof_c_zero']).encode('utf-8') 
            serialized_prodProofs = json.dumps(deser_comsandproofs['prodProofs']).encode('utf-8') 
            
            for i in range(self.n):
                proofandshares.append(json.dumps(deser_comsandproofs['proofs_c'][i]).encode('utf-8'))       
        
        serialized_ephemeralpublicsecretkey = lib.pyKeyEphemeralGen(self.srs_kzg['Pk'], self.public_keys)
        deserialized_ephemeralpublicsecretsharedkey = json.loads(serialized_ephemeralpublicsecretkey.decode('utf-8'))
        
        serialized_ephemeralpublickey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralpublickey']).encode('utf-8')
        serialized_ephemeralsecretkey  = json.dumps(deserialized_ephemeralpublicsecretsharedkey['ephemeralsecretkey']).encode('utf-8')

        dispersal_msg_list = [None] * n
        shared_keys = [None] * n
        serialized_publickeys = json.loads(self.public_keys.decode('utf-8'))
        for i in range(n):
            shared_keys[i] = lib.pySharedKeysGen_sender(json.dumps(serialized_publickeys[i]).encode('utf-8'), serialized_ephemeralsecretkey)
            if self.mode == "avss_without_proof":
                z = proofandshares[i]
            if self.mode == "avss_with_proof":
                z = (proofandshares[i], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs)
            dispersal_msg_list[i] = SymmetricCrypto.encrypt(str(shared_keys[i]).encode(), z)


        
        return dumps((serialized_commitment, serialized_ephemeralpublickey)), dispersal_msg_list

    #@profile
    def _handle_dealer_msgs(self, dealer_id, tag, dispersal_msg, rbc_msg):
        all_shares_valid = True
        
        serialized_commitment, serialized_ephemeral_public_key = loads(rbc_msg)
        
        serialized_private_key = json.loads(json.loads(self.private_key.decode('utf-8')))

        serialized_sharedkey =  lib.pySharedKeysGen_recv(serialized_ephemeral_public_key, json.dumps(serialized_private_key[f'{dealer_id}']).encode('utf-8'))
        # self.tagvars[tag]['shared_key'] = serialized_sharedkey
        # self.tagvars[tag]['ephemeral_public_key'] = serialized_ephemeral_public_key
        try:
            if self.mode == "avss_without_proof":
                serialized_proofandshares = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
            if self.mode == "avss_with_proof":
                serialized_proofandshares, serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs = SymmetricCrypto.decrypt(str(serialized_sharedkey).encode(), dispersal_msg)
                
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False
         
         
        if all_shares_valid:
            if self.mode == "avss_without_proof":
                if lib.pyBatchVerify(self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id) == int(1):
                    self.tagvars[tag]['commitments'] = serialized_commitment
                    self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
                else:
                    all_shares_valid = False
            if self.mode == "avss_with_proof":
                if lib.pyBatchVerify(
                    self.srs_kzg['Vk'], serialized_commitment, serialized_proofandshares, self.my_id
                    ) == int(1) and lib.pyBatchhiddenverify(self.srs_kzg['Vk'], 
                    self.tagvars[tag]['committment_ab'], serialized_zkProof_ab, dealer_id) == int(1) and lib.pyBatchhiddenzeroverify(self.srs_kzg['Vk'], 
                    serialized_commitment, serialized_zkProof_c_zero) == int(1) and lib.pyProdverify(
                    self.srs_kzg['Vk'], serialized_zkProof_ab, serialized_zkProof_c_zero, serialized_prodProofs) == int(1):
                        self.tagvars[tag]['commitments'] = serialized_commitment
                        self.tagvars[tag]['proofsandshares'] = serialized_proofandshares
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
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)   

     
class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        # TODO: Add the share recovery 
        pass
        # if not self.tagvars[tag]['in_share_recovery']:
        #     return
        # ls = len(self.tagvars[tag]['commitments']) // (self.t + 1)
        # send, recv, multicast = self.tagvars[tag]['io']
        # if not self.tagvars[tag]['finished_interpolating_commits']:
        #     all_commits = [ [] for l in range(ls)]
        #     for l in range(ls):
        #         known_commits = self.tagvars[tag]['commitments'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #         known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
        #         # line 502
        #         interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
        #         #interpolated_commits = known_commits + known_commits + known_commits
        #         all_commits[l] = known_commits + interpolated_commits
        #     self.tagvars[tag]['all_commits'] = all_commits
        #     self.tagvars[tag]['finished_interpolating_commits'] = True

        #     #init some variables we'll need later
        #     self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
        #     self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
        #     self.tagvars[tag]['r1_aux_coords_l'] = [[] for l in range(ls)]
        #     self.tagvars[tag]['r2_aux_coords_l'] = [[] for l in range(ls)]
        #     self.tagvars[tag]['sent_r2'] = False
        #     self.tagvars[tag]['r1_set'] = set()
        #     self.tagvars[tag]['r2_set'] = set()
            
        #     if self.tagvars[tag]['all_shares_valid']:
        #         logger.debug("[%d] prev sent r1", self.my_id)
        #         all_evalproofs = [ [] for l in range(ls)]
        #         all_points = [ [] for l in range(ls)]
        #         all_aux_points = [[] for l in range(ls)]
        #         for l in range(ls):
        #             # the proofs for the specific shares held by this node
        #             known_evalproofs = self.tagvars[tag]['witnesses'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
        #             # line 504
        #             interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
        #                                     range(self.t + 1, self.n)]
        #             #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
        #             all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
        #             # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
        #             known_points = self.tagvars[tag]['shares'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
        #             mypoly = self.poly.interpolate(known_point_coords)
        #             interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
        #             all_points[l] = known_points + interpolated_points

        #             #auxes
        #             known_auxes = self.tagvars[tag]['auxes'][l * (self.t + 1): (1 + l) * (self.t + 1)]
        #             known_aux_coords = [[i + 1, known_auxes[i]] for i in range(self.t + 1)]
        #             my_aux_poly = self.poly.interpolate(known_aux_coords)
        #             interpolated_aux_points = [my_aux_poly(i + 1) for i in range(self.t + 1, self.n)]
        #             all_aux_points[l] = known_auxes + interpolated_aux_points


        #         logger.debug("[%d] in between r1", self.my_id)
        #         # lines 505-506
        #         for j in range(self.n):
        #             send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)] , [ all_aux_points[l][j] for l in range(ls)], [all_evalproofs[l][j] for l in range(ls)]))
        #         logger.debug("[%d] sent r1", self.my_id)

        # if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
        #     logger.debug("[%d] prev sent r2", self.my_id)
        #     _, points, aux_points, proofs = avss_msg
        #     all_commits = self.tagvars[tag]['all_commits']
        #     if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, aux_points, proofs):
        #         if sender not in self.tagvars[tag]['r1_set']:
        #             self.tagvars[tag]['r1_set'].add(sender)
        #             for l in range(ls):
        #                 self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
        #                 self.tagvars[tag]['r1_aux_coords_l'][l].append([sender, aux_points[l]])
        #             #r1_coords.append([sender, point])
        #         if len(self.tagvars[tag]['r1_set']) == self.t + 1:
        #             #r1_poly = self.poly.interpolate(r1_coords)
        #             r1_poly_l = [ [] for l in range(ls)]
        #             r1_aux_poly_l = [[] for l in range(ls)]
        #             for l in range(ls):
        #                 r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
        #                 r1_aux_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_aux_coords_l'][l])
        #             for j in range(self.n):
        #                 r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
        #                 r1_aux_points_j = [r1_aux_poly_l[l](j) for l in range(ls)]
        #                 #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
        #                 send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j, r1_aux_points_j))
        #             self.tagvars[tag]['sent_r2'] = True
        #             logger.debug("[%d] sent r2", self.my_id)

        # if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
        #     _, points, aux_points = avss_msg
        #     if sender not in self.tagvars[tag]['r2_set']:
        #         self.tagvars[tag]['r2_set'].add(sender)
        #         #r2_coords.append([sender, point])
        #         for l in range(ls):
        #             self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
        #             self.tagvars[tag]['r2_aux_coords_l'][l].append([sender, aux_points[l]])
        #     if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
        #         # todo, replace with robust interpolate that takes at least 2t+1 values
        #         # this will still interpolate the correct degree t polynomial if all points are correct
        #         r2_poly_l = [ [] for l in range(ls)]
        #         r2_aux_poly_l = [[] for l in range(ls)]
        #         shares = []
        #         auxes = []
        #         for l in range(ls):
        #             r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
        #             shares += [r2_poly(i) for i in range(self.t + 1)]
        #             r2_aux_poly = self.poly.interpolate(self.tagvars[tag]['r2_aux_coords_l'][l])
        #             auxes += [r2_aux_poly(i) for i in range(self.t + 1)]
        #         multicast((HbAVSSMessageType.OK, ""))

        #         self.tagvars[tag]['all_shares_valid'] = True
        #         self.tagvars[tag]['shares'] = shares
        #         self.tagvars[tag]['auxes'] = auxes