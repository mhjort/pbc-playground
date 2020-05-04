(ns pbc-playground.core
  (:require [clojure.test :refer [deftest is]]
            [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys :as buddy-keys]
            [buddy.core.dsa :as dsa])
  (:import (java.time OffsetDateTime)))

(defn- sha256 [s]
  (-> (buddy-hash/sha256 s)
      (codecs/bytes->hex)))

(defn- read-private-key [key-name]
  (buddy-keys/private-key (str "keys/" key-name ".pem") "secret"))

(defn- read-public-key [key-name]
  (buddy-keys/public-key (str "keys/" key-name ".pem")))

(def signing-algorithm :rsassa-pss+sha256)

(def nodes
  {"OP" {:id "OP" :private-key (read-private-key "op-private") :public-key (read-public-key "op-public")}
   "Nordea" {:id "Nordea" :private-key (read-private-key "nordea-private") :public-key (read-public-key "nordea-public")}
   })
(def op-node (get nodes "OP"))
(def nordea-node (get nodes "Nordea"))

(defn- sign [data private-key]
  (-> (dsa/sign data {:key private-key :alg signing-algorithm})
      (codecs/bytes->hex)))

(defn- verify-sign [data signature public-key]
  (dsa/verify data (codecs/hex->bytes signature) {:key public-key :alg signing-algorithm}))

(defn- serialize [data]
  (pr-str data))

(defn- sign-transaction [{:keys [block] :as tx} {:keys [id private-key]}]
  (let [serialized (serialize block)]
    (update tx :signatures assoc id (sign serialized private-key))))

(defn- generate-transaction [data previous signers]
  (let [block {:timestamp (OffsetDateTime/now)
               :validator "(fn [input output] (= output (inc input)))"
               :data data
               :signers signers
               :precedingHash (:hash previous)}
        serialized (serialize block)]
    {:hash (sha256 serialized)
     :block block
     :signatures {}}))

(defn- generate-and-sign-transaction [data previous {:keys [id] :as node}]
  (let [tx (generate-transaction data previous [id])]
   (sign-transaction tx node)))

;(sign-transaction (generate-and-sign-transaction 1 nil op-node) nordea-node)

(defn- add-transaction [chain transaction]
  (cons transaction chain))

(defn- add-new-transaction [chain data node]
  (let [previous(first chain)
        transaction (generate-and-sign-transaction data previous node)]
    (add-transaction chain transaction)))

(defn- validate-transaction-hash [input output]
  (and (= (:hash input) (-> output :block :precedingHash))
       (= (:hash output) (sha256 (serialize (:block output))))))

(defn- validate-transaction-code [input output]
  (let [validator-fn (-> output :block :validator read-string eval)]
    (validator-fn (-> input :block :data) (-> output :block :data))))

(defn- validate-required-signatures [{:keys [signatures block]} nodes]
  (loop [required-signers (:signers block)]
    (if (empty? required-signers)
      true
      (let [required-signer (first required-signers)
            signature (get signatures required-signer)]
        (if (and signature
                 (verify-sign (serialize block)
                              (get signatures required-signer)
                              (:public-key (get nodes required-signer))))
          (recur (rest required-signers))
          false)))))

(defn- validate-transaction [input output nodes]
  (and (validate-transaction-hash input output)
       (validate-transaction-code input output)
       (validate-required-signatures output nodes)))

(defn- validate-chain [chain nodes]
  (if (= 1 (count chain))
    true
    (if-not (validate-transaction (second chain) (first chain) nodes)
      false
      (validate-chain (rest chain) nodes))))

(let [transaction1 (generate-and-sign-transaction 1 nil op-node)
      transaction2 (generate-and-sign-transaction 3 transaction1 op-node)]
  (validate-transaction-code transaction1 transaction2))

(let [transaction1 (generate-transaction 1 nil ["OP" "Nordea"])
      signed (-> transaction1
                 (sign-transaction op-node)
                 (sign-transaction nordea-node))]
  (validate-required-signatures signed nodes))

(deftest valid-chain
  (let [chain (-> (add-new-transaction [] 1 op-node)
                  (add-new-transaction 2 op-node))]
    (is (validate-chain chain nodes))))

(deftest valid-chain-with-only-genesis-block
  (let [chain (-> (add-new-transaction [] 1 op-node))]
    (is (validate-chain chain nodes))))

(deftest code-contract-fails
  (let [chain (-> (add-new-transaction [] 1 op-node)
                  (add-new-transaction 2 op-node)
                  (add-new-transaction 4 op-node))]
    (is (not (validate-chain chain nodes)))))

(deftest hash-contract-fails
  (let [real-transaction (generate-and-sign-transaction 1 nil op-node)
        fake-transaction (assoc (generate-and-sign-transaction 2 real-transaction op-node) :hash "fake-hash")
        invalid-chain (-> (add-transaction [] real-transaction)
                          (add-transaction fake-transaction))]
    (is (not (validate-chain invalid-chain nodes)))))
