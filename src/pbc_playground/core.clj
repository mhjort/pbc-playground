(ns pbc-playground.core
  (:require [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys :as buddy-keys]
            [buddy.core.dsa :as dsa])
  (:import (java.time OffsetDateTime)))

(defn- sha256 [s]
  (-> (buddy-hash/sha256 s)
      (codecs/bytes->hex)))

(def private-key (buddy-keys/private-key "keys/private.pem" "secret"))
(def public-key (buddy-keys/public-key "keys/public.pem"))
(def signing-algorithm :rsassa-pss+sha256)

(defn- sign [data]
  (-> (dsa/sign data {:key private-key :alg signing-algorithm})
      (codecs/bytes->hex)))

(defn- verify-sign [data signature]
  (dsa/verify data (codecs/hex->bytes signature) {:key public-key :alg signing-algorithm}))

(defn- serialize [data]
  (pr-str data))

(defn- generate-transaction [data previous]
  (let [block {:timestamp (OffsetDateTime/now)
               :validator "(fn [input output] (= output (inc input)))"
               :data data
               :precedingHash (:hash previous)}
        serialized (serialize block)]
    {:hash (sha256 serialized)
     :block block
     :signature (sign serialized)}))

(defn- add-transaction [chain transaction]
  (cons transaction chain))

(defn- add-new-transaction [chain data]
  (let [previous(first chain)
        transaction (generate-transaction data previous)]
    (add-transaction chain transaction)))

(defn- validate-transaction-hash [input output]
  (and (= (:hash input) (-> output :block :precedingHash))
       (= (:hash output) (sha256 (serialize (:block output))))))

(defn- validate-transaction-code [input output]
  (let [validator-fn (-> output :block :validator read-string eval)]
    (validator-fn (-> input :block :data) (-> output :block :data))))

(defn- validate-signature [{:keys [signature block]}]
  (verify-sign (serialize block) signature))

(defn- validate-transaction [input output]
  (and (validate-transaction-hash input output)
       (validate-transaction-code input output)
       (validate-signature output)))

(defn- validate-chain [chain]
  (if (= 1 (count chain))
    true
    (if-not (validate-transaction (second chain) (first chain))
      false
      (validate-chain (rest chain)))))

(let [transaction1 (generate-transaction 1 nil)
      transaction2 (generate-transaction 3 transaction1)]
  (validate-transaction-code transaction1 transaction2))

(let [chain (-> (add-new-transaction [] 1)
    (add-new-transaction 2))]
  (validate-chain chain))

(let [chain (-> (add-new-transaction [] 1))]
  (validate-chain chain))

(let [chain (-> (add-new-transaction [] 1)
                (add-new-transaction 2)
                (add-new-transaction 4))]
  (validate-chain chain))

(let [real-transaction (generate-transaction 1 nil)
      fake-transaction (assoc (generate-transaction 2 real-transaction) :hash "fake-hash")
      invalid-chain (-> (add-transaction [] real-transaction)
                        (add-transaction fake-transaction))]
  (validate-chain invalid-chain))
