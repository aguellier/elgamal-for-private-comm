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
 * This file contains a toy, (very insecure and inefficient implementation) 
 * of ElGamal. Because we use php, without gmp, we work only on groups which
 *elements are lower than INT_MAX
 *
 * This file contains: 
 * - Some fonctions to generate primes or check primality, along with gcd
 *   and euler totient fonctions
 * - Functions to generate, check and manipulate groups (notably, functions to 
 *   perform modular exponentiation, inverse and k-th root)
 * - The ElGamal cryptosystem primitives 
 * - ElGamal homomorphic operations (multiplication, plaintext multiplication 
 *   and scalar exponentiation)
 * - Unit-test-like functions to check the ElGamal implementation and 
 *   homomorphic operations
 *
 * This file is meant to be included as library
 */

//Debug : 0 = No log, 1 = Only important stuff, 10 = Very detailled
const _DEBUG = 1;

$N_FIRST_PRIMES = array(2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973);


/*****************************************************************************************
 *****************************************************************************************
 **************************** Utilities
 *****************************************************************************************
 ****************************************************************************************/

function wait_CLI() {
	echo "Press ENTER to continue...\n";
	//INSECURE !
	fgets(fopen("php://stdin", "r"));
}

function power_set($array) {
	$results = array(array( ));

	foreach ($array as $element)
		foreach ($results as $combination)
			array_push($results, array_merge(array($element), $combination));

	return $results;
}

function get_primes($n) {
	global $N_FIRST_PRIMES;
	$n = abs($n);
	if($n <= count($N_FIRST_PRIMES))
		return array_slice($N_FIRST_PRIMES, 0, $n);

	$res = range(2, $n);
	foreach($res as $crible) {
		if($crible > sqrt($n)) break;
		foreach($res as $i => $candidate) {
			if($candidate != $crible && $candidate % $crible == 0) {
				unset($res[$i]);
			}
		}
	}
	
	return $res;
}

function get_safe_primes($n, $r) {
	$n = abs($n);
	$res = array();
	
	$primes = get_primes($n);
	$last_prime = array_pop($primes);
	if($last_prime == null)
		return $res;
       	array_push($primes, $last_prime);	
	
	foreach($primes as $q) {
		$p = $r*$q+1;
		if($p > $last_prime)
			return $res;
		if(in_array($p, $primes))
			$res[] = array($r*$q+1, $q);
	}
	return $res;
}

function factorisation($n) {
	$n = abs($n);
	if($n <= 3)
		return array($n => 1);

	global $N_FIRST_PRIMES;
	$ndiv2 = ceil($n/2);
	$res = array();
	foreach($N_FIRST_PRIMES as $p) {
		if($p > $ndiv2)
			return $res;
		else {
			while($n % $p == 0) {
				$res[] = $p;
				$n = $n / $p;
			}
		}
	}
	return $res;
}

function is_prime($n) {
	$n = abs($n);
	if($n < 2)
		return false;

	global $N_FIRST_PRIMES;
	$sqrtn = ceil(sqrt($n));
	foreach($N_FIRST_PRIMES as $p) {
		if($p > $sqrtn)
			return true;
		else if($n % $p == 0)
			return false;

	}

	return false;
}

function gcd($x, $y) {
	$x = abs($x);
	$y = abs($y);

	if($x+$y == 0)
		return 0;
	else {
		$z = $x;
		while($x > 0) {
			$z = $x;
			$x = $y%$x;
			$y = $z;
		}
		return $z;
	}
}

function euler_totient($n) {
	$n = abs($n);
	if(is_prime($n))
		return $n-1;
	else if($n <= 1)
		return $n;
		
	$phin = 1;
	$factors = factorisation($n);
	$factors = array_count_values($factors);
	foreach($factors as $p => $frequency) 
		$phin *= ($p-1)*pow($p, $frequency-1);

	return $phin;
}



/*****************************************************************************************
 *****************************************************************************************
 **************************** Groups and group operations
 *****************************************************************************************
 ****************************************************************************************/
//array("G" => the group, "gen" => generator, "order" => q, "modulo" => p)
function gen_schnorr_group($r, $q) {
	$p = $r*$q+1;

	$Zpx = range(1, $p-1);
	
	if(_DEBUG >= 5) echo "Generating Shnorr groups with p = $p, q = $q : \n";

	$h = 1;
	for($h = 1; $h < $p; $h++) {
		if(pow($h, $r) % $p != 1) {
			break;
		}
	}

	if(_DEBUG >= 7) echo "Value for h found : h = $h. \n";

	$g = pow($h, $r) % $p;
	if(_DEBUG >= 7) echo "Generator g is : g = $g\n";

	if(_DEBUG >= 6) echo "Generating subgroup of Z_$p^* of order q = $q using g = $g...\n";
	$subgroup = array();
	for($i = 1; $i <= $q; $i++) {
		$value = modular_exp($g, $i, $p);
		array_push($subgroup, $value);
	}
	sort($subgroup);
	
	if(_DEBUG >= 5){
		echo "{ ";
		foreach($subgroup as $i) echo $i, ", ";
		echo "}\n";
	}
	
	return array("G" => $subgroup, "gen" => $g, "order" => $q, "modulo" => $p);
}

function find_subgroup($group) {
	$G = $group["G"];
	$g = $group["gen"];
	$q = $group["order"];
	$p = $group["modulo"];

	foreach($G as $sub_g_candidate) {
		//Discard trivial subgroup <1>
		if($sub_g_candidate == 1) continue;

		$subgroup = array();
		for ($i = 1; $i <= $q; $i++) {
			$subgroup_elem = modular_exp($sub_g_candidate, $i, $p);
			if(!in_array($subgroup_elem, $G))
				break;

			array_push($subgroup, $subgroup_elem);
			if($subgroup_elem == 1 && $i != $q) {//Discard trivial subgroup G
				return array("G" => $subgroup, "gen" => $sub_g_candidate, "order" => $i, "modulo" => $p);
			}
		}
	}
	return false;
}

function check_group($group) {
	list($G, $g, $order, $modulo) = array_values($group);
	
	if(_DEBUG >= 8) echo "Checking group...\n";

	if(count(array_unique($G)) != $order || count($G) != $order) {
		if(_DEBUG >= 1) echo "\nERROR : Group is invalid, The number of elements in the subgroup is ", count(array_unique($G)), " != $order\n";
		return false;
	}

	foreach($G as $i) {
		foreach($G as $j) {
			if(!in_array(modular_mult($i, $j, $modulo), $G)) {
				if(_DEBUG >= 1) echo "\nERROR : Group is invalid, $i*$j mod $modulo is not in the subgroup !\n";
				return false;
			}
		}
	}

	if(_DEBUG >= 8) echo "Done checking group.\n";
	return true;
}

function modular_exp($base, $exp, $modulo) {
	$base = $base % $modulo;
	$exp = $exp % euler_totient($modulo);
	
	if($exp == 0) return 1;
	
	//Note : we shoud be using the function modular_mult to multuiply
	////the base with itself, but I can't be bothered
	$cumul = $base;	
	for($i = 1; $i < $exp; $i++) {
		$cumul *= $base;
		$cumul = $cumul % $modulo;
	}

	return $cumul;
}

function modular_mult($op1, $op2, $modulo) {
	$op1 = $op1 % $modulo;
	$op2 = $op2 % $modulo;

	if($op1 == 0 || $op2 == 0) return 0;

	$cumul = $op1;
	for($i = 1; $i < $op2; $i++) {
		$cumul += $op1;
		$cumul = $cumul % $modulo;
	}

	return $cumul;
}

function modular_inverse($op, $modulo) {
	return modular_exp($op, euler_totient($modulo)-1, $modulo);
}

//Computes the k-th roots of x modulo some number (does not have to be prime)
function modular_kth_root($x, $k, $modulo) {
	$x = $x % $modulo;
	
	$inv_exp_k = modular_inverse($k, euler_totient($modulo));
	return modular_exp($x, $inv_exp_k, $modulo);

}

function check_modularkthroot() {
	for ($i = 0; $i < 1000; $i++) {
		$r = 4;
		$safe_primes = get_safe_primes(1000, $r);
		$aux = rand(0, count($safe_primes)-1);
		$p = rand(10, 1000);//$safe_primes[$aux][0];
		echo "Avec p = $p...\n";
		do {
			$a = rand($p+1, 3*$p);
		} while(gcd($a, $p) != 1);
		do {
			$k = rand($p+1, 4*$p);
		} while(gcd($k, euler_totient($p)) != 1);
		$apowk = modular_exp($a, $k, $p);
		$res = modular_kth_root($apowk, $k, $p);
		echo "p = $p, a = ",($a%$p),", k = $k, apowk = $apowk mod $p, et res = $res\n";
		if($res != ($a % $p)) {
			echo "ERREUR\n";
			exit;
		}
	}
}

/*****************************************************************************************
 *****************************************************************************************
 **************************** ElGamal Cryptosystem
 *****************************************************************************************
 ****************************************************************************************/

//Return array("pk" => array("h" => h=g^x, "group" => array("G" => the group, "gen" => generator, "order" => q, "modulo" => p), "sk" => x) 
function ElG_KeyGen($lambda, $r) {
	//Generate the proper parameter q, with |q| >= lambda
	//The idea is to take the minimum q just above 2^lambda
	$powlambda = pow(2, $lambda);
	$max_retries = 5;
	$i = 0;
	do {
		$safe_primes = get_safe_primes($powlambda*pow(2, 1+$i)*$r, $r);
		$nb_safe_primes = count($safe_primes);
		if($nb_safe_primes == 0 || $safe_primes[$nb_safe_primes-1][1] < $powlambda) {
			$q = 0;
		} else if($nb_safe_primes == 1) {
			$q = $safe_primes[0][1];
		} else {
			$candidate_q = $safe_primes[$nb_safe_primes-1][1];
			$j = 1;
			while($candidate_q > $powlambda) {
				$candidate_q = $safe_primes[$nb_safe_primes-$j-1][1];
				$j++;
			}
			$q = $safe_primes[$nb_safe_primes-$j+1][1];
		}
		$i++;
	} while($q < $powlambda && $i < $max_retries);

	//If no possible q was found, return false
	if($i == $max_retries) {
		if(_DEBUG >= 1) echo "KeyGen : impossible to find a suitable q for lambda = $lambda and r = $r. Aborting key generation.\n";
		return false;
	}


	return ElG_KeyGen_alt($r, $q);
}

function ElG_KeyGen_alt($r, $q) {
	//Generate the secret parameter x (secret key)
	$x = rand(1, $q-1);
	if(_DEBUG >= 5) echo "KeyGen : Secret key is : x = $x\n";

	return ElG_PubKeyGen($r, $q, $x);
}

function ElG_PubKeyGen($r, $q, $x) {
	//Generate the proper group
	$p = $r*$q+1;
	$group = gen_schnorr_group($r, $q);

	//Generate the public parameter h = g^x (public keys)
	$h = modular_exp($group["gen"], $x, $group["modulo"]);
	if(_DEBUG >= 5) echo "KeyGen : Public key is h = g^x = $h mod p\n";
	
	return array("pk" => array("h" => $h, "group" => $group), "sk" => $x);
}

function ElG_Enc($m, $pk) {
	$group = $pk["group"];
	if(false && !in_array($m, $group["G"])) {
		if(_DEBUG >=1) echo "ERROR : impossible to encrypt message $m, message not in group.\n";
		return false;
	}

	$r = rand(0, $group["order"]-1);
	
	$c1 = modular_exp($group["gen"], $r, $group["modulo"]);
	$c2 = modular_exp($pk["h"], $r, $group["modulo"]);
	$c2 = modular_mult($m, $c2, $group["modulo"]);

	if(_DEBUG >= 6) echo "Encryption of $m is ($c1, $c2)\n";

	return array($c1, $c2);
}

function ElG_Dec($c, $pk, $sk) {
	$group = $pk["group"];
	list($c1, $c2) = $c;

	if(_DEBUG >= 8) echo "Decryption of ($c1, $c2)...\n";

	//Operation is $c2/($c1^$x) <=> $c2*($c1^{x.(q-2)}) because varpĥi(vraphi(p)) = varphi(2q) = q-1

	//Could have been done in precomputation
	$inv_c1 = modular_inverse($c1, $group["modulo"]);
	if(_DEBUG >= 8) echo "\t c1 = $c1, inv_c1 = $inv_c1\n";
	if(_DEBUG >= 8) echo "\t c1*inv_c1 = ", modular_mult($c1, $inv_c1, $group["modulo"]), "\n";
	
	//Actual decryption
	$m = modular_mult($c2, modular_exp($inv_c1, $sk, $group["modulo"]), $group["modulo"]);

	if(_DEBUG >= 6) echo "Decryption of ($c1, $c2) is $m\n";

	return $m;
}

function check_ElGEncDec_correctness($pk, $sk) {
	$group = $pk["group"];
	
	foreach($group["G"] as $m) {
		if(_DEBUG >= 8) echo "Checking ElGamal Enc/Dec for $m...";
		$c = ElG_Enc($m, $pk);

		if($m != ElG_Dec($c, $pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : Decryption Error for m = $m and c = (",$c[0], ",", $c[1], ")\n";
			return false;
		}

		if(_DEBUG >= 8) echo "\n";
	}

	return true;
}

function ElG_Rerand($c, $pk) {
	$group = $pk["group"];

	$r = rand(0, $group["order"]-1);
	
	return array(modular_mult($c[0], modular_exp($group["gen"], $r, $group["modulo"]), $group["modulo"]),
		modular_mult($c[1], modular_exp($pk["h"], $r, $group["modulo"]), $group["modulo"]));
}

function check_ElGRerand_correctness($pk, $sk) {
	$group = $pk["group"];
	
	foreach($group["G"] as $m) {
		if(_DEBUG >= 8) echo "Checking ElGamal Enc/Dec for $m...";
		$c = ElG_Enc($m, $pk);
		
		$c = ElG_Rerand($c, $pk);

		if($m != ElG_Dec($c, $pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : Re-randomization Error for m = $m\n";
			return false;
		}

		if(_DEBUG >= 8) echo "\n";
	}

	return true;
}

/*****************************************
 *  ElGamal homomorphic operations 
 ****************************************/
function ElG_Mult($c1, $c2, $pk) {
	$group = $pk["group"];
	return array(modular_mult($c1[0], $c2[0], $group["modulo"]), modular_mult($c1[1], $c2[1], $group["modulo"]));
}

function check_ElGMult_correctness($pk, $sk) {
	$group = $pk["group"];
	
	foreach($group["G"] as $m1) {
		foreach($group["G"] as $m2) {
			if(_DEBUG >= 8) echo "Checking ElGamal mult for $m1 and $m2...";
			$c1 = ElG_Enc($m1, $pk);
			$c2 = ElG_Enc($m2, $pk);
			$cmult = ElG_Mult($c1, $c2, $pk);

			if(modular_mult($m1, $m2, $group["modulo"]) != ElG_Dec($cmult, $pk, $sk)) {
				if(_DEBUG >= 1) echo "\nERROR : ElGamal homomorphic multiplication error for m1 = $m1 and m2 = $m2\n";
				return false;
			}

			if(_DEBUG >= 8) echo "\n";
		}
	}

	return true;

}


function ElG_PlainMult($c, $plain, $pk) {
	$group = $pk["group"];
	if(false && !in_array($plain, $group["G"])) {
		if(_DEBUG >= 1) echo "ERROR : Can not multiply ElGamal ciphertext by plaintext $plain, plaintext not in group.\n";
		return false;
	}
	$c[1] = modular_mult($c[1], $plain, $group["modulo"]);
	return $c;
}

function check_ElGPlainMult_correctness($pk, $sk) {
	$group = $pk["group"];

	foreach($group["G"] as $m) {
		foreach($group["G"] as $plain) {
			if(_DEBUG >= 8) echo "Checking ElGamal plain mult for $m and $plain...";
			$c = ElG_Enc($m, $pk);
			$cmult = ElG_PlainMult($c, $plain, $pk);

			if(modular_mult($m, $plain, $group["modulo"]) != ElG_Dec($cmult, $pk, $sk)) {
				if(_DEBUG >= 1) echo "\nERROR : ElGamal homomorphic plain multiplication error for m = $m and plain = $plain\n";
				return false;
			}

			if(_DEBUG >= 8) echo "\n";
		}
	}

	return true;

}


function ElG_ScalarExp($c, $scalar, $pk) {
	$group = $pk["group"];

	return array(modular_exp($c[0], $scalar, $group["modulo"]), modular_exp($c[1], $scalar, $group["modulo"]));
}

function check_ElGScalarExp_correctness($pk, $sk) {
	$group = $pk["group"];
	$Zq = range(0, $group["order"]-1);
	
	foreach($group["G"] as $m) {
		foreach($Zq as $scalar) {
			if(_DEBUG >= 8) echo "Checking ElGamal scalar exp for $m and $scalar...";
			$c = ElG_Enc($m, $pk);
			$cmult = ElG_ScalarExp($c, $scalar, $pk);

			if(modular_exp($m, $scalar, $group["modulo"]) != ElG_Dec($cmult, $pk, $sk)) {
				if(_DEBUG >= 1) echo "\nERROR : ElGamal homomorphic scalar exponentiation error for m = $m and scalar = $scalar\n";
				return false;
			}

			if(_DEBUG >= 8) echo "\n";
		}
	}

	return true;

}


/**** Final check of ElGamal (enc, dec, mult, scalar mult and exp) ****/
//If needed, a compelte check of ElGamal and its homomorphic properties can be run with the following function
function check_ElG_correctness($lambda, $r) {
	//Generate a somewhat proper parameter q, with |q| >= lambda
	$safe_primes = get_safe_primes(pow(2, $lambda+1), $r);
	$q = $safe_primes[count($safe_primes)-1][1];

	$Zq = range(0, $q-1);
	foreach($Zq as $x) {
		if(_DEBUG >= 2) echo "Testing ElGamal with q = $q and x = $x : ";
		$keys = ElG_PubKeyGen($r, $q, $x);
		if(!$keys) {
			if(_DEBUG >= 1) echo "\nERROR : failure during key generation for q = $q and x = $x\n";
			return false;
		}

		list($pk, $sk) = array_values($keys);
		if(!check_ElGEncDec_correctness($pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : check_ElGEncDec_correctness failed with sk = x = $x\n";
			return false;
		} else if(_DEBUG >= 2) echo "EncDec : OK";

		if(!check_ElGRerand_correctness($pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : check_ElGRerand_correctness failed with sk = x = $x\n";
			return false;
		} else if(_DEBUG >= 2) echo ", Rerand : OK";
			
		if(!check_ElGMult_correctness($pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : check_ElGMult_correctness failed with sk = x = $x\n";
			return false;
		} else if(_DEBUG >= 2) echo ", Mult : OK"; 
			
		if(!check_ElGPlainMult_correctness($pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : check_ElGPlainMult_correctness failed with sk = x = $x\n";
			return false;
		} else if(_DEBUG >= 2) echo ", PlainMult : OK";
			
		if(!check_ElGScalarExp_correctness($pk, $sk)) {
			if(_DEBUG >= 1) echo "\nERROR : check_ElGScalarExp_correctness failed with sk = x = $x\n";
			return false;
		} else if(_DEBUG >= 2) echo ", ScalarExp : OK";

		if(_DEBUG >= 2) echo "\n";

	}
	return true;
}

?>
