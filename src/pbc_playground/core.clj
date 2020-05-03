(ns pbc-playground.core
  (:require [buddy.core.hash :as buddy-hash]
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
  {"Bank" {:id "Bank" :private-key (read-private-key "private") :public-key (read-public-key "public")}})
(def bank-node (get nodes "Bank"))

(defn- sign [data private-key]
  (-> (dsa/sign data {:key private-key :alg signing-algorithm})
      (codecs/bytes->hex)))

(defn- verify-sign [data signature public-key]
  (dsa/verify data (codecs/hex->bytes signature) {:key public-key :alg signing-algorithm}))

(defn- serialize [data]
  (pr-str data))

(defn- generate-transaction [data previous {:keys [id private-key]}]
  (let [block {:timestamp (OffsetDateTime/now)
               :validator "(fn [input output] (= output (inc input)))"
               :data data
               :signers [id]
               :precedingHash (:hash previous)}
        serialized (serialize block)]
    {:hash (sha256 serialized)
     :block block
     :signatures {id (sign serialized private-key)}}))

(defn- add-transaction [chain transaction]
  (cons transaction chain))

(defn- add-new-transaction [chain data node]
  (let [previous(first chain)
        transaction (generate-transaction data previous node)]
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
      (let [required-signer (first required-signers)]
        (if (verify-sign (serialize block)
                     (get signatures required-signer)
                     (:public-key (get nodes required-signer)))
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

(let [transaction1 (generate-transaction 1 nil bank-node)
      transaction2 (generate-transaction 3 transaction1 bank-node)]
  (validate-transaction-code transaction1 transaction2))

(let [chain (-> (add-new-transaction [] 1 bank-node)
                (add-new-transaction 2 bank-node))]
  (validate-chain chain nodes))

(let [chain (-> (add-new-transaction [] 1 bank-node))]
  (validate-chain chain nodes))

(let [chain (-> (add-new-transaction [] 1 bank-node)
                (add-new-transaction 2 bank-node)
                (add-new-transaction 4 bank-node))]
  (validate-chain chain nodes))

(let [real-transaction (generate-transaction 1 nil bank-node)
      fake-transaction (assoc (generate-transaction 2 real-transaction bank-node) :hash "fake-hash")
      invalid-chain (-> (add-transaction [] real-transaction)
                        (add-transaction fake-transaction))]
  (validate-chain invalid-chain nodes))
