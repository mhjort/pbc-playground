(ns pbc-playground.core
  (:require [buddy.core.hash :as buddy-hash]
            [buddy.core.codecs :as codecs])
  (:import (java.time OffsetDateTime)))

(defn- sha256 [s]
(-> (buddy-hash/sha256 s)
    (codecs/bytes->hex)))

(defn- generate-block [data previous]
  (let [block {:index (if previous
                        (inc (:index previous))
                        0) ;Genesis
               :timestamp (OffsetDateTime/now)
               :data data
               :precedingHash (:hash previous)}]
    (assoc block :hash (sha256 (pr-str block)))))

(defn- add-new-block [chain data]
  (let [previous(first chain)
        block (generate-block data previous)]
    (cons block chain)))

(-> (add-new-block [] "a")
    (add-new-block "b"))
