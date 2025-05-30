# Compile libpbl.so

```
cd ./src
make python
cd ../
make 
```

# Run 
## Aqara M2 Hub
TBD
## Aqara M3 Hub
1. Get a clone image of factory partition
2. python3 ./aqara_property_db_editor.py -r ./p3.img


## Peter Graf's Free GPL Open Source Software

* * * * *

All software published here is published under the [The GNU General
Public License][] or the [The GNU Lesser General Public License][]

### PBL - The Program Base Library

PBL is an GPL open source C library of functions that can be used in a C
or C++ project. PBL is highly portable and compiles warning free on
Linux gcc, MAC OS X and Windows Microsoft Visual C++ 2010 Express
Edition.
The code of the PBL library includes the following modules:

[**PBL BASE**][] - Some base functions, see **pbl\_\*** functions,

[**PBL COLLECTION**][] - An open source C implementation of a collection
used by the list and set implementations.

[**PBL LIST**][] - An open source C implementation of array lists and
linked lists similar to the [Java List][] interface, see **pblList\***
functions,

-   **pblArrayList**: -- C array list, C-ArrayList, array list in C,
    ArrayList in C, List in C
    Open source C resizable-array implementation equivalent to the [Java
    ArrayList][] class.

    Implements most optional list operations, and permits all elements,
    including NULL. In addition to implementing the List operations,
    this module provides methods to manipulate the size of the array
    that is used internally to store the list.

    The size, isEmpty, get, set, iterator, and listIterator operations
    run in constant time. The add operation runs in amortized constant
    time, that is, adding n elements requires O(n) time. All of the
    other operations run in linear time (roughly speaking). The constant
    factor is low compared to that for the LinkedList implementation.

    Each pblArrayList instance has a capacity. The capacity is the size
    of the array used to store the elements in the list. It is always at
    least as large as the list size. As elements are added to an
    ArrayList, its capacity grows automatically. The details of the
    growth policy are not specified beyond the fact that adding an
    element has constant amortized time cost.

    An application can increase the capacity of an ArrayList instance
    before adding a large number of elements using the ensureCapacity
    operation. This may reduce the amount of incremental reallocation.
-   [**pblLinkedList**][**PBL LIST**]: -- C linked list, C-LinkedList,
    linked list in C, LinkedList in C, List in C
    Open source C linked list implementation equivalent to the [Java
    LinkedList][] class.

    Implements most optional list operations, and permits all elements
    (including null). In addition to implementing the List operations,
    this module provides uniformly named methods to get, remove and
    insert an element at the beginning and end of the list. These
    operations allow linked lists to be used as a stack, queue, or
    double-ended queue (deque).

    The module implements the Queue operations, providing
    first-in-first-out queue operations for add, poll, etc. Other stack
    and deque operations could be easily recast in terms of the standard
    list operations.

    All of the operations perform as could be expected for a
    doubly-linked list. Operations that index into the list will
    traverse the list from the beginning or the end, whichever is closer
    to the specified index.
-   [**pblIterator**][]: -- C list iterator, C-ListIterator, list
    iterator in C, ListIterator in C
    Open source C Iterator implementation equivalent to the [Java
    ListIterator][] interface.

    An iterator for lists that allows the programmer to traverse the
    list in either direction, modify the list during iteration, and
    obtain the iterator's current position in the list. A ListIterator
    has no current element; its cursor position always lies between the
    element that would be returned by a call to previous() and the
    element that would be returned by a call to next(). In a list of
    length n, there are n+1 valid index values, from 0 to n, inclusive.

    Note that the remove() and set(Object) methods are not defined in
    terms of the cursor position; they are defined to operate on the
    last element returned by a call to next() or previous().

[**PBL Set**][] - An open source C implementation of hash sets and tree
sets similar to the [Java Set][] interface, see **pblSet\*** functions,

-   **pblHashSet**: -- C hash set, C-HashSet, hash set in C, HashSet in
    C, Set in C
    Open source C resizable hash set implementation equivalent to the
    [Java HashSet][] class.

    Hash sets make no guarantees as to the iteration order of the set;
    in particular, it does not guarantee that the order will remain
    constant over time. This module does not permit the NULL element.

    Hash sets offer constant time performance for the basic operations
    (add, remove, contains and size), assuming the hash function
    disperses the elements properly among the buckets. Iterating over
    this set requires time proportional to the sum of the HashSet
    instance's size (the number of elements) plus the "capacity" of the
    instance (the number of buckets). Thus, it's very important not to
    set the initial capacity too high (or the load factor too low) if
    iteration performance is important. [][**PBL Set**]
-   **pblTreeSet**: -- C tree set, C-TreeSet, tree set in C, TreeSet in
    C, Set in C
    Open source C avl-tree-based balanced tree set implementation
    equivalent to the [Java TreeSet][] class.

    Tree sets guarantees that the sorted set will be in ascending
    element order, sorted according to the natural order of the
    elements, or by the comparator provided.

    This implementation provides guaranteed log(n) time cost for the
    basic operations (add, remove and contains).

[**PBL Map**][] - An open source C implementation of hash maps and tree
maps similar to the [Java Map][] interface, see **pblMap\*** functions,

-   **pblHashMap**: -- C hash map, C-HashMap, hash map in C, HashMap in
    C, Map in C \
     Open source C resizable hash map implementation equivalent to the
    [Java HashMap][] class. \
     Hash maps make no guarantees as to the iteration order of the set;
    in particular, it does not guarantee that the order will remain
    constant over time. \
     Hash maps offer constant time performance for the basic operations
    (add, remove, contains and size), assuming the hash function
    disperses the elements properly among the buckets. Iterating over
    this map requires time proportional to the sum of the HashMap
    instance's size (the number of elements) plus the "capacity" of the
    instance (the number of buckets). Thus, it's very important not to
    set the initial capacity too high (or the load factor too low) if
    iteration performance is important.
    [][**PBL Map**]
-   **pblTreeMap**: -- C tree map, C-TreeMap, tree map in C, TreeMap in
    C, Map in C \
     Open source C avl-tree-based balanced tree map implementation
    equivalent to the [Java TreeMap][] class. \
     Tree maps guarantee that the sorted map will be in ascending
    element order, sorted according to the natural order of the
    elements, or by the comparator provided. \
     This implementation provides guaranteed log(n) time cost for the
    basic operations (add, remove and contains).

[**PBL HEAP**][] -- Heap in C, C heap, heap in C, C-Heap, binary heap in
C, binary min-max heap in C

[**PBL PRIORITY QUEUE**][] -- PriorityQueue in C, C priority queue,
priority queue in C, Heap in C, C-Heap, binary heap in C, binary max
heap in C

[**PBL HASH**][]: -- C hash table, C-HashTable
An open source C memory hash table implementation, see **pblHt\***
functions,

**Features**
-   random access lookups
-   sequential access
-   regression test frame

[**PBL KEYFILE**][]: -- C key file, C-KeyFile
An open source C key file implementation, see **pblKf\*** functions,

**Features**
-   ultra fast B\* tree implementation for random lookups
-   transaction handling
-   sequential access methods
-   embedable small footprint, < 35 Kb
-   arbitrary size files, up to 4 terrabytes
-   arbitrary number of records per file, up to 2 \^\^ 48 records
-   duplicate keys
-   advanced key compression for minimal size B trees
-   keylength up to 255 bytes
-   regression test frame

[**PBL ISAM**][]: -- C isam file, C-IsamFile
An open source C ISAM file implementation, see **pblIsam\*** functions

**Features**
-   ultra fast B\* tree implementation for random lookups
-   transaction handling
-   sequential access methods
-   embedable small footprint, < 75 Kb
-   arbitrary size files, up to 4 terrabytes
-   arbitrary number of records per file, up to 2 \^\^ 48 records
-   duplicate keys and unique keys
-   advanced key compression for minimal size index files
-   keylength up to 255 bytes per index
-   keylength up to 1024 per record
-   regression test frame

[**AvlDictionary<TKey,TValue\>**][]: -- C\# .NET Avl-Tree based generic
IDictionary<TKey,TValue\>
AvlDictionary<TKey,TValue\> is an open source C\# Avl-Tree based generic
IDictionary<TKey,TValue\> implementation. See the [**AvlDictionary
documentation**][].

**Features**
-   implements generic IDictionary<TKey, TValue\> interface
-   implements generic ICollection<KeyValuePair<TKey, TValue\>\>
    interface
-   implements generic IEnumerable<KeyValuePair<TKey, TValue\>\>
    interface
-   [Serializable]

In order to use AvlDictionary<TKey,TValue\> copy
[**AvlDictionary.cs**][] to your solution and use the AVL-Tree based
generic AvlDictionary<TKey,TValue\> like you use the hash based generic
Dictionary<TKey,TValue\>.

## VERSIONS:

## GET PBL:

-   See the PBL [documentation][].
-   Download the PBL [Version 1.04 tar source][] file.
-   Take a look at the PBL [sources][].
-   Take a look at [Spam Probe][], a project that uses PBL.

* * * * *

copyright (C) 2001 - 2010 by Peter Graf

  [The GNU General Public License]: http://www.gnu.org/licenses/licenses.html#GPL
  [The GNU Lesser General Public License]: http://www.gnu.org/licenses/licenses.html#LGPL
  [**PBL BASE**]: http://www.mission-base.com/peter/source/pbl/doc/base.html
  [**PBL COLLECTION**]: http://www.mission-base.com/peter/source/pbl/doc/collection.html
  [**PBL LIST**]: http://www.mission-base.com/peter/source/pbl/doc/list.html
  [Java List]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/List.html
  [Java ArrayList]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/ArrayList.html
  [Java LinkedList]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/LinkedList.html
  [**pblIterator**]: http://www.mission-base.com/peter/source/pbl/doc/iterator.html
  [Java ListIterator]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/ListIterator.html
  [**PBL Set**]: http://www.mission-base.com/peter/source/pbl/doc/set.html
  [Java Set]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/Set.html
  [Java HashSet]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/HashSet.html
  [Java TreeSet]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/TreeSet.html
  [**PBL Map**]: http://www.mission-base.com/peter/source/pbl/doc/map.html
  [Java Map]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/Map.html
  [Java HashMap]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/HashMap.html
  [Java TreeMap]: http://java.sun.com/j2se/1.5.0/docs/api/java/util/TreeMap.html
  [**PBL HEAP**]: http://www.mission-base.com/peter/source/pbl/doc/heap.html
  [**PBL PRIORITY QUEUE**]: http://www.mission-base.com/peter/source/pbl/doc/priorityQueue.html
  [**PBL HASH**]: http://www.mission-base.com/peter/source/pbl/doc/hash.html
  [**PBL KEYFILE**]: http://www.mission-base.com/peter/source/pbl/doc/keyfile.html
  [**PBL ISAM**]: http://www.mission-base.com/peter/source/pbl/doc/isamfile.html
  [**AvlDictionary<TKey,TValue\>**]: ./AvlDictionary/class_com_1_1_mission___base_1_1_pbl_1_1_avl_dictionary_3_01_t_key_00_01_t_value_01_4.html
  [**AvlDictionary documentation**]: ./AvlDictionary/
  [**AvlDictionary.cs**]: ./AvlDictionary.cs
  [documentation]: http://www.mission-base.com/peter/source/pbl/doc/
  [Version 1.04 tar source]: pbl_1_04.tar.gz
  [sources]: http://www.mission-base.com/peter/source/pbl/
  [Spam Probe]: http://spamprobe.sourceforge.net/
