<?php
/*
 * Copyright or © or Copr. Antoine Guellier (2014)
 *
 * antoine.guellier@supelec.fr
 *
 * This software is a computer program whose purpose is to provide a 
 * proof-of-concept implementation of the ElGamal-based privacy preserving
 * routing protocol described in the paper "Homomorphic Cryptography-based
 * Privacy-Preserving Network Communications", by Christophe Bidan, Antoine 
 * Guellier and Nicolas Prigent and available at
 * ????
 *
 * This software is governed by the CeCILL license under French law and
 * abiding by the rules of distribution of free software. You can use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty and the software's author, the holder of the
 * economic rights, and the successive licensors have only limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading, using, modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean that it is complicated to manipulate, and that also
 * therefore means that it is reserved for developers and experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and, more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 * */


/**************************
 * This file contains uses the "library" toy_elgamal.php
 * It provides a proof-of-concept implementation of the arithmetics 
 * involved in the privacy-preserving network communication protocol
 * described in the article "Homomorphic Cryptography-based
 * Privacy-Preserving Network Communications", by Christophe Bidan, Antoine 
 * Guellier and Nicolas Prigent.
 *
 * This file contains a main loop that performs a certain number of tests
 * for the "route proposition" and "route initialization" procedures of
 * the protocol.
 * The main goals are to verify the arithmetics and EtGamal homomorphic
 * operations, and to attest that the protocol is correct. As a side goal, 
 * this program measures the time required for route propositions or 
 * initialization.
 *
 * This program does not take in account the communication delays, and
 * do not simulate any notion of networking. It focuses on arithmetics.
 * The threshold homomorphic part of the route initialization procedure
 * is also not represented.
 *
 * The program also provides a way to measure running times of the 
 * KeyGen, Enc, Dec, Mult, PlainMult, ScalarExp and ReRand procedures.
 *
 * This code is neither efficient nor secure, and is not meant to be.
 */



//Include the ElGamal system and the functions to manipulate groups
require_once("toy_elgamal.php");


//What to simulate (all procedures are performed in a serial fashion, so as to test the whole system)
$PROP_ROUTE = true;
$INIT_ROUTE = true;
$TIMINGS_ELGAMAL = true;

//Timings
$total_time_prop_route = 0;
$total_time_init_route = 0;


$r = 2;
$lambda = 10; 

//Uncomment these lines to test the correctness of ElGamal as coded in the file "toy_elgamal.php"
//if(!check_ElG_correctness($lambda, $r)) {
	//echo "\nERROR : scheme was detected incorrect (by function check_ElG_correctness)\n";
	//echo "Aborting.\n";
	//exit;
//}


//Generate the keys of the destination D
$keys_D = ElG_KeyGen($lambda, $r);
if($keys_D == false) {
	echo "Error : Key Generation failed for D with lambda = $lambda and r = $r...\n";
	exit;
}
list($pk_D, $sk_D) = array_values($keys_D);
$group = $pk_D["group"];
$q = $group["order"];


echo "Keys generated. Group is of order q = $q, generator is g = ",$group["gen"]," and p = ",$group["modulo"],"\n\n"; 

$limit = 1000; //Number of tests to perform
$echo_when_OK = false; //Print every tests on stdout

//Main loop
for($i = 0; $i < $limit; $i++) {
	echo "Progression : $i/$limit\n";

	$dst_D = rand(2, $group["modulo"]-1);
	$ID_D = $group["G"][array_rand($group["G"])];
	$src_P = $group["G"][array_rand($group["G"])];
	
	//Simulation : computation in the clear
	$LocalID_DP_theoretic = modular_mult($ID_D, modular_exp($group["gen"], $dst_D*$src_P, $group["modulo"]), $group["modulo"]);


	/* Protocol for route proposition. D is the destination. P is the proposee.
	 * D -> P : HEnc_{PK_D}(g^{dst_D})
	 * P -> D : HEnc_{PK_D}(r.g^{dst_D.src_P}) 
	 * D -> P : r*ID_D.g^{dst_D.src_P} = r*LocalID_D^P
	 *       Then P divides by r
	 */
	if($PROP_ROUTE) {
		$time_aux = microtime(true);
		//Done by D
		$gpowdstD = modular_exp($group["gen"], $dst_D, $group["modulo"]);
		$cgpowdstD = ElG_Enc($gpowdstD, $pk_D);

		//Done by P
		$r_tmp = $group["G"][array_rand($group["G"])];
		$cgpowdstDsrcP = ElG_ScalarExp($cgpowdstD, $src_P, $pk_D);
		$cgpowdstDsrcP = ElG_PlainMult($cgpowdstDsrcP, $r_tmp, $pk_D);
		$cgpowdstDsrcP = ElG_Rerand($cgpowdstDsrcP, $pk_D);

		//Done by D
		$gpowdstDsrcP = ElG_Dec($cgpowdstDsrcP, $pk_D, $sk_D);
		$rtmpLocalID_DP = modular_mult($ID_D, $gpowdstDsrcP, $group["modulo"]);

		//Done by P
		$LocalID_DP = modular_mult($rtmpLocalID_DP, modular_inverse($r_tmp, $group["modulo"]), $group["modulo"]);

		$total_time_prop_route += microtime(true) - $time_aux;

		if($LocalID_DP != $LocalID_DP_theoretic) {
			echo "Error in route proposition: for q = $q, p = ",$group["modulo"],", ID_D = $ID_D, s_D = $dst_D, k_P = $src_P, r_tmp = $r_tmp, we have $LocalID_DP != $LocalID_DP_theoretic\n";
			exit;
		} elseif($echo_when_OK) {
			echo "Route proposition test #$i OK: for q = $q, p = ",$group["modulo"],", ID_D = $ID_D, s_D = $dst_D, k_P = $src_P, r_tmp = $r_tmp, we have $LocalID_DP = $LocalID_DP_theoretic\n";
		}
	}
	
	/* Protocol for route initialization, between source S and auxiliary V, towards destination D
	 * S -> V : THEnc_{PK_*}(dst_D.r)
	 *        S et V perform a 1 round threshold decryption and V obtains dst_D.r 
	 * V -> S : HEnc_{PK_V}(g^{dst_D.r.src_V})
	 * S -> V : HEnc_{PK_V}(ID_D.g^{dst_D.src_V}) = HEnc(LocalID_DV)
	 */
	if($INIT_ROUTE) {
		//Note: now P takes the place of V, so V = P in the following
		$src_V = $src_P;


		//Simulation of the threshold homomorphic part of the protocol
		do {
			$r_tmp = $group["G"][array_rand($group["G"])];
		} while(gcd($r_tmp, $group["modulo"]-1) != 1);
		$trap = $r_tmp*$dst_D;

		//Done by V (key generation is considered as done offline, prior to network setup)
		$keys_V = ElG_KeyGen_alt($r, $q);
		if($keys_V == false) {
			echo "Error: Key Generation failed for V with lambda = $lambda and r = $r...\n";
			exit;
		}
		list($pk_V, $sk_V) = array_values($keys_V);
		
		$time_aux = microtime(true);

		$gpowdstDrtmpsrcV = modular_exp($group["gen"], modular_mult($trap, $src_V, $group["modulo"]-1), $group["modulo"]);
		$cgpowdstDrtmpsrcV = ElG_Enc($gpowdstDrtmpsrcV, $pk_V);

		//Done by S
		$inv_rtmp_pmin1 = modular_inverse($r_tmp, $group["modulo"]-1);
		$cgpowdstDsrcV = ElG_ScalarExp($cgpowdstDrtmpsrcV, $inv_rtmp_pmin1, $pk_V);
		$cLocalID_DV = ElG_PlainMult($cgpowdstDsrcV, $ID_D, $pk_V);
		$cLocalID_DV = ElG_Rerand($cLocalID_DV, $pk_V);

		//Done by V
		$LocalID_DV = ElG_Dec($cLocalID_DV, $pk_V, $sk_V);

		$total_time_init_route += microtime(true)-$time_aux;

		//Because V = P, we should have that the LocalID_DV found be equal to LocalID_DP_theoretic from above
		if($LocalID_DV != $LocalID_DP_theoretic) {
			echo "Error in route initialization: for q = $q, p = ",$group["modulo"],", ID_D = $ID_D, s_D = $dst_D, k_V = $src_V, r_tmp = $r_tmp, we have $LocalID_DV != $LocalID_DP_theoretic\n";
			exit;
		} elseif($echo_when_OK) {
			echo "Route initialization test #$i OK: for q = $q, p = ",$group["modulo"],", ID_D = $ID_D, s_D = $dst_D, k_V = $src_V, r_tmp = $r_tmp,we have $LocalID_DV = $LocalID_DP_theoretic\n";
		}
	}
	if($echo_when_OK)
		wait_CLI();
}

if($PROP_ROUTE || $INIT_ROUTE) {
	echo "Simulated : ";
	if($PROP_ROUTE)
		echo "Route proposition";
	if($INIT_ROUTE && $PROP_ROUTE)
		echo " and ";
	if($INIT_ROUTE)
		echo "Route initialization";
	echo " on $limit sets of parameters. All is OK !\n";

	echo "Mean time for route proposition : ",(1000*$total_time_prop_route/$limit),"ms, mean time for route initialization: ", (1000*$total_time_init_route/$limit),"ms \n\n";
}

if($TIMINGS_ELGAMAL) {

	echo "Measuring running times of ElGamal primitives and homomorphic operations...\n";

	$limit = 1000;
	$cumul = array("keygen" => 0, "enc" => 0, "dec" => 0, "mult" => 0, "plainmult" => 0, "scexp" => 0, "rerand" => 0);

	$keys = ElG_KeyGen($lambda, $r);
	$q = $keys["pk"]["group"]["order"];

	for($i = 0; $i < $limit; $i++) {
		$begin_time = microtime(true);
		$keys = ElG_KeyGen_alt($r, $q);
		if($keys == false) {
			echo "Error at key generation...";
			exit;
		}
		$end_time = microtime(true);
		$cumul["keygen"] += 1000*($end_time-$begin_time);

		list($pk, $sk) = array_values($keys);
		$group = $pk["group"];
		$a = $group["G"][array_rand($group["G"])];
		$b = $group["G"][array_rand($group["G"])];

		$begin_time = microtime(true);
		$ca = ElG_Enc($a, $pk);
		$end_time = microtime(true);
		$cumul["enc"] += 1000*($end_time-$begin_time);

		$begin_time = microtime(true);
		ElG_Dec($ca, $pk, $sk);
		$end_time = microtime(true);
		$cumul["dec"] += 1000*($end_time-$begin_time);

		$cb = ElG_Enc($b, $pk);

		$begin_time = microtime(true);
		ElG_Mult($ca, $cb, $pk);
		$end_time = microtime(true);
		$cumul["mult"] += 1000*($end_time-$begin_time);

		$begin_time = microtime(true);
		ElG_PlainMult($ca, $b, $pk);
		$end_time = microtime(true);
		$cumul["plainmult"] += 1000*($end_time-$begin_time);

		$begin_time = microtime(true);
		ElG_ScalarExp($ca, $b, $pk);
		$end_time = microtime(true);
		$cumul["scexp"] += 1000*($end_time-$begin_time);

		$begin_time = microtime(true);
		ElG_Rerand($ca, $pk);
		$end_time = microtime(true);
		$cumul["rerand"] += 1000*($end_time-$begin_time);
	}

	echo "For $limit tests and a security of $lambda bits, mean ElGamal running times are:\n";
	echo "\tKeyGen: ",($cumul["keygen"]/$limit),"ms\n";
	echo "\tEnc: ",($cumul["enc"]/$limit),"ms\n";
	echo "\tDec: ",($cumul["dec"]/$limit),"ms\n";
	echo "\tMult: ",($cumul["mult"]/$limit),"ms\n";
	echo "\tPlainMult: ",($cumul["plainmult"]/$limit),"ms\n";
	echo "\tScalarExp: ",($cumul["scexp"]/$limit),"ms\n";
	echo "\tRerand: ",($cumul["rerand"]/$limit),"ms\n";

}

?>
