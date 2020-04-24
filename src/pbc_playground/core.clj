(ns pbc-playground.core
  (:require [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs])
  (:import (java.time OffsetDateTime)))

(defn- sha256 [s]
(-> (buddy-hash/sha256 s)
    (codecs/bytes->hex)))

(defn- serialise-state [state]
  (pr-str state))

(defn- generate-transaction [data previous]
  (let [data {:timestamp (OffsetDateTime/now)
              :validator "(fn [input output] (= output (inc input)))"
              :data data
              :precedingHash (:hash previous)}]
     {:hash (sha256 (serialise-state data)) :data data}))

(defn- add-transaction [chain transaction]
  (cons transaction chain))

(defn- add-new-transaction [chain data]
  (let [previous(first chain)
        transaction (generate-transaction data previous)]
    (add-transaction chain transaction)))

(defn- validate-transaction-hash [input output]
  (and (= (:hash input) (-> output :data :precedingHash))
       (= (:hash output) (sha256 (serialise-state (:data output))))))

(defn- validate-transaction-code [input output]
  (let [validator-fn (-> output :data :validator read-string eval)]
    (validator-fn (-> input :data :data) (-> output :data :data))))

(defn- validate-transaction [input output]
  (and (validate-transaction-hash input output)
       (validate-transaction-code input output)))

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
