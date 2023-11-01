https://github.com/mstrobel/procyon/wiki/Java-Decompiler

GUI Front Ends
Don't want to use the command line? Try one of these GUI front-ends for Procyon:

SecureTeam Java Decompiler
A JavaFX-based decompiler front-end with fast and convenient code navigation. Download it, or launch it directly from your browser.

Luyten(https://github.com/deathmarine/Luyten, inactive)
An open source front-end by deathmarine.

Bytecode Viewer(https://github.com/Konloch/bytecode-viewer, active) is an open source Java decompilation, disassembly, and debugging suite by @Konloch. It can produce decompiled sources from several modern Java decompilers, including Procyon, CFR, and FernFlower.

Helios(https://github.com/helios-decompiler/standalone-app, inactive) is similar to Bytecode Viewer. But is a completely new and independent project, which uses SWT instead of Swing.

Alternatives
There are other Java Decompiler projects underway that you should check out:

CFR(https://github.com/leibnitz27/cfr, active) by Lee Benfield is well on its way to becoming the premier Java Decompiler. Lee and I actually work for the same company and share regression tests. We're engaged in a friendly competition to see who can deliver a better decompiler. Based on his progress thus far, there's a very good chance he will win--at least on decompiling obfuscated code :).
Krakatau(https://github.com/Storyyeller/Krakatau, inactive since 2021) by Robert Grosse, written in Python, includes a robust verifier. It focuses on translating arbitrary bytecode into valid Java code, as opposed to reconstructing the original code.
Candle(https://github.com/bradsdavis/candle-decompiler, inactive for 8/9 years) by Brad Davis, developer of JBoss Cake, is an early but promising work in progress.
Fernflower(https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine) an analytical Java decompiler.
JD GUI(https://github.com/java-decompiler/jd-gui, inactive for 2 years) is an Decompiler, which comes with its own GUI. All is licensed under GPLv3. Like CFR the source for the decompiler itself, is not published, but you have the right to decompile the bionaries. And the binaries are under an OpenSource-License (CFR is under the MIT-license and JD Core is under the GPLv3 license)
















http://www.javadecompilers.com/

Select a decompiler
 Procyon - fast decompiler for modern Java
 CFR - very good and well-supported decompiler for modern Java
 JDCore (very fast)
 Jadx, fast and with Android support
 Fernflower
 JAD (very fast, but outdated)


Until recently, you needed to use a Java decompiler and all of them were either unstable, obsolete, unfinished, or in the best case all of the above. And, if not, then they were commercial. The obsoleteness was typically proved by the fact that they can only decompile JDK 1.3 bytecode.
The only so-so working solution was to take the .class file and pre-process it, so it becomes JDK 1.3 compatible, and then run Jad over it (one of those older, but better decompilers).

But recently, a new wave of decompilers has forayed onto the market:  Procyon,  CFR,  JD,  Fernflower,  Krakatau,  Candle.
Here's a list of decompilers presented on this site:
 CFR
This free and open-source decompiler is available here: http://www.benf.org/other/cfr/
Author: Lee Benfield

Regularly updated, CFR is able to decompile all the modern Java features:
Java 7: String switches
Java 8: lambdas
Java 9: modules
Java 11: dynamic constants
Java 12: Kotlin style "switch expressions"
Java 14: 'instance of' pattern match and 'Record types'

It'll even make a decent go of turning class files from other JVM langauges back into java!

 JD
free for non-commercial use only, http://jd.benow.ca/
Author: Emmanuel Dupuy

Updated in 2015. Has its own visual interface and plugins to Eclipse and IntelliJ . Written in C++, so very fast. Supports Java 5.

 Procyon
open-source, https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler
Author: Mike Strobel

Updated in 2019. Handles language enhancements from Java 5 and beyond, up to Java 8, including:
Enum declarations
Enum and String switch statements
Local classes (both anonymous and named)
Annotations
Java 8 Lambdas and method references (i.e., the :: operator).

 Fernflower
open-source, https://github.com/fesh0r/fernflower
Author: Egor Ushakov

Updated in 2015. Very promising analytical Java decompiler, now becomes an integral part of IntelliJ 14. (https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler)
Supports Java up to version 6 (Annotations, generics, enums)

 JAD
given here only for historical reason. Free, no source-code available, jad download mirror
Author: Pavel Kouznetsov

Probably, this is the most popular Java decompiler, but primarily of this age only. Written in C++, so very fast.
Outdated, unsupported and does not decompile correctly Java 5 and later.