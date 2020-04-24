(ns pbc-playground.core
  (:require [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs])
  (:import (java.time OffsetDateTime)))

(defn- sha256 [s]
(-> (buddy-hash/sha256 s)
    (codecs/bytes->hex)))

(defn- generate-transaction [data previous]
  (let [data {:timestamp (OffsetDateTime/now)
              :data data
              :precedingHash (:hash previous)}]
    {:input previous
     :output {:hash (sha256 (pr-str data)) :data data}}))

(defn- add-transaction [chain transaction]
  (cons (:output transaction) chain))

(defn- add-new-transaction [chain data]
  (let [previous(first chain)
        transaction (generate-transaction data previous)]
    (add-transaction chain transaction)))

(defn- validate-transaction [input output]
  (and (= (:hash input) (-> output :data :precedingHash))
       (= (:hash output) (sha256 (pr-str (:data output))))))

(defn- validate-chain [chain]
  (if (= 1 (count chain))
    true
    (if-not (validate-transaction (second chain) (first chain))
      false
      (validate-chain (rest chain)))))

(let [chain (-> (add-new-transaction [] "a")
    (add-new-transaction "b"))]
  (validate-chain chain))

(let [chain (-> (add-new-transaction [] "a"))]
  (validate-chain chain))

(let [chain (-> (add-new-transaction [] "a")
                (add-new-transaction "b")
                (add-new-transaction "c"))]
  (validate-chain chain))

(let [real-transaction (generate-transaction "a" nil)
      fake-transaction (assoc-in (generate-transaction "fake" real-transaction) [:output :hash] "fake-hash")
      invalid-chain (-> (add-transaction [] real-transaction)
                        (add-transaction fake-transaction))]
  (validate-chain invalid-chain))
