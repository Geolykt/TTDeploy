package de.geolykt.ttdeploy;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.decompiler.PrintStreamLogger;
import org.jetbrains.java.decompiler.main.decompiler.SingleFileSaver;
import org.jetbrains.java.decompiler.main.extern.IFernflowerPreferences;

import me.coley.cafedude.InvalidClassException;
import me.coley.cafedude.classfile.ClassFile;
import me.coley.cafedude.classfile.ConstPool;
import me.coley.cafedude.classfile.Field;
import me.coley.cafedude.classfile.Method;
import me.coley.cafedude.classfile.attribute.Attribute;
import me.coley.cafedude.classfile.attribute.CodeAttribute;
import me.coley.cafedude.classfile.attribute.InnerClassesAttribute;
import me.coley.cafedude.classfile.attribute.InnerClassesAttribute.InnerClass;
import me.coley.cafedude.classfile.attribute.SignatureAttribute;
import me.coley.cafedude.classfile.constant.CpClass;
import me.coley.cafedude.classfile.constant.CpFieldRef;
import me.coley.cafedude.classfile.constant.CpNameType;
import me.coley.cafedude.classfile.constant.CpString;
import me.coley.cafedude.classfile.constant.CpUtf8;
import me.coley.cafedude.classfile.instruction.Instruction;
import me.coley.cafedude.classfile.instruction.IntOperandInstruction;
import me.coley.cafedude.classfile.instruction.Opcodes;
import me.coley.cafedude.io.ClassFileReader;
import me.coley.cafedude.io.ClassFileWriter;
import me.coley.cafedude.io.InstructionReader;
import software.coley.llzip.ZipArchive;
import software.coley.llzip.ZipIO;
import software.coley.llzip.part.LocalFileHeader;
import software.coley.llzip.strategy.DeflateDecompressor;
import software.coley.llzip.util.ByteData;
import software.coley.llzip.util.ByteDataUtil;

public class TTDeploy {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Path gameDir;
        if (System.getProperty("game_dir") != null) {
            gameDir = Paths.get(System.getProperty("game_dir"));
        } else {
            gameDir = Utils.getGameDir(Utils.STEAM_APPNAME).toPath();
        }
        if (gameDir == null) {
            System.err.println("I was unable to locate your Game directory. You may wish to pass it explicitly through the \"game_dir\" system property.");
            return;
        } else {
            System.out.println("Located Theotown directory at: " + gameDir);
        }

        Path theotownJar = gameDir.resolve("TheoTown66.lby");
        if (Files.notExists(theotownJar)) {
            System.err.println("Unable to find the game's pseudo-jar \"TheoTown66.lby\" expected to be located at " + theotownJar.toAbsolutePath());
            return;
        }

        // Find mavenLocal
        Path userhome = Path.of(System.getProperty("user.home"));
        Path mavenLocal = userhome.resolve(".m2/repository");

        // We need LL-Java-ZIP to read the jar
        ZipArchive theotownArchive;
        try {
            theotownArchive = ZipIO.readJvm(theotownJar);
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Unable to read Theotown's pseudo-jar.");
            return;
        }

        DeflateDecompressor deflator = new DeflateDecompressor();
        ByteData manifestData = null;
        for (LocalFileHeader header : theotownArchive.getLocalFiles()) {
            if (header.getFileNameAsString().endsWith("META-INF/MANIFEST.MF")) {
                try {
                    manifestData = header.decompress(deflator);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
        }
        if (manifestData == null) {
            System.err.println("Theotown's pseudo-jar did not contain a META-INF/MANIFEST.MF!");
            return;
        }
        String manifest = ByteDataUtil.toString(manifestData);
        String mainClass = null;
        for (String line : manifest.split("[\r\n]")) {
            String[] d = line.split(":");
            if (d.length == 0 || line.length() == 0) {
                continue;
            }
            if (d.length != 2) {
                throw new IllegalStateException("Manifest contains strange line: \"" + line + "\"");
            }
            if (d[0].equals("Main-Class")) {
                mainClass = d[1].trim();
            }
        }
        if (mainClass == null) {
            throw new IllegalStateException("Unable to find main class");
        }
        String mainClassFile = mainClass.replace('.', '/') + ".class";
        String versionName = null;
        for (LocalFileHeader header : theotownArchive.getLocalFiles()) {
            if (header.getFileNameAsString().endsWith(mainClassFile)) {
                try {
                    ByteData classData = header.decompress(deflator);
                    ClassFileReader reader = new ClassFileReader();
                    ClassFile cf = reader.read(ByteDataUtil.toByteArray(classData));
                    for (Method m : cf.getMethods()) {
                        String name = ((CpUtf8) cf.getCp(m.getNameIndex())).getText();
                        String desc = ((CpUtf8) cf.getCp(m.getTypeIndex())).getText();
                        if (name.equals("main") && desc.equals("([Ljava/lang/String;)V")) {
                            for (Attribute attr : m.getAttributes()) {
                                if (attr instanceof CodeAttribute) {
                                    InstructionReader insnReader = new InstructionReader();
                                    List<Instruction> insns = insnReader.read((CodeAttribute) attr);
                                    Instruction last = null;
                                    for (Instruction insn : insns) {
                                        if (insn.getOpcode() == Opcodes.PUTSTATIC) {
                                            IntOperandInstruction intInsn = (IntOperandInstruction) insn;
                                            CpFieldRef target = (CpFieldRef) cf.getCp(intInsn.getOperand());
                                            String targetC = ((CpUtf8) cf.getCp(((CpClass) cf.getCp(target.getClassIndex())).getIndex())).getText();
                                            CpNameType targetNT = ((CpNameType) cf.getCp(target.getNameTypeIndex()));
                                            String targetN = ((CpUtf8) cf.getCp(targetNT.getNameIndex())).getText();
                                            String targetD = ((CpUtf8) cf.getCp(targetNT.getTypeIndex())).getText();
                                            if (targetC.equals("info/flowersoft/theotown/crossplatform/TheoTown") && targetN.equals("VERSION_NAME") && targetD.equals("Ljava/lang/String;")) {
                                                versionName = ((CpUtf8) cf.getCp(((CpString) cf.getCp(((IntOperandInstruction) Objects.requireNonNull(last)).getOperand())).getIndex())).getText();
                                            }
                                        }
                                        last = insn;
                                    }
                                }
                            }
                        }
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                } catch (InvalidClassException ice) {
                    throw new IllegalStateException(ice);
                }
            }
        }
        if (versionName == null) {
            throw new IllegalStateException("Unable to extract version name out of " + mainClass);
        }
        System.out.println("Identified theotown version: " + versionName);
        Path stagingDir = mavenLocal.resolve("de/geolykt/theotown").resolve(versionName);
        try {
            Files.createDirectories(stagingDir);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Creating potemkin jar");
        ClassFileReader cfr = new ClassFileReader();
        ClassFileWriter cfw = new ClassFileWriter();
        byte[] buffer = new byte[4096];
        Path potemkinJar = stagingDir.resolve("theotown-" + versionName + "-potemkin.jar");
        try (ZipOutputStream zipOut = new ZipOutputStream(Files.newOutputStream(potemkinJar))) {
            Path workJar = gameDir.resolve("work.jar");
            try (ZipOutputStream cleansedOut = new ZipOutputStream(Files.newOutputStream(workJar))) {
                for (LocalFileHeader header : theotownArchive.getLocalFiles()) {
                    if (!header.getFileNameAsString().endsWith(".class")) {
                        // We only care about .class files
                        continue;
                    }
                    if (header.getFileNameAsString().endsWith("module-info.class")) {
                        continue; // We don't care about module-info.class files. Plus apparently there are multiple module-info.class files shaded into the theotown jar.
                    }
                    ByteData decompressed = header.decompress(deflator);
                    cleansedOut.putNextEntry(new ZipEntry(header.getFileNameAsString()));
                    decompressed.transferTo(cleansedOut, buffer);
                    ClassFile cf;
                    try {
                        cf = cfr.read(ByteDataUtil.toByteArray(decompressed));
                    } catch (InvalidClassException e) {
                        e.printStackTrace();
                        continue;
                    }
                    ConstPool cp = new ConstPool();
                    int minor = cf.getVersionMinor();
                    int major = cf.getVersionMajor();
                    int acc = cf.getAccess();
                    Map<String, Integer> cpUTF8 = new HashMap<>();
                    Map<Integer, Integer> cpClass = new HashMap<>();
                    int className = getUTFIndex(cf.getName(), cpUTF8, cp);
                    int superName = getUTFIndex(cf.getSuperName(), cpUTF8, cp);
                    int ownClass = getClassIndex(className, cpClass, cp);
                    int superClass = getClassIndex(superName, cpClass, cp);

                    List<Integer> interfaces = new ArrayList<>();

                    for (Integer itf : cf.getInterfaceIndices()) {
                        interfaces.add(transfer((CpClass) cf.getCp(itf.intValue()), cf, cpUTF8, cpClass, cp));
                    }

                    List<Field> fields = new ArrayList<>();

                    for (Field f : cf.getFields()) {
                        List<Attribute> attributes = new ArrayList<>();
                        for (Attribute a : f.getAttributes()) {
                            if (a instanceof SignatureAttribute) {
                                SignatureAttribute s = (SignatureAttribute) a;
                                int signatureIndex = getUTFIndex(((CpUtf8) cf.getCp(s.getSignatureIndex())).getText(), cpUTF8, cp);
                                int nameIndex = getUTFIndex("Signature", cpUTF8, cp);
                                attributes.add(new SignatureAttribute(nameIndex, signatureIndex));
                            }
                        }
                        int nameIndex = getUTFIndex(((CpUtf8) cf.getCp(f.getNameIndex())).getText(), cpUTF8, cp);
                        int typeIndex = getUTFIndex(((CpUtf8) cf.getCp(f.getTypeIndex())).getText(), cpUTF8, cp);
                        fields.add(new Field(attributes, f.getAccess(), nameIndex, typeIndex));
                    }

                    List<Method> methods = new ArrayList<>();

                    for (Method m : cf.getMethods()) {
                        List<Attribute> attributes = new ArrayList<>();
                        for (Attribute a : m.getAttributes()) {
                            if (a instanceof SignatureAttribute) {
                                SignatureAttribute s = (SignatureAttribute) a;
                                int signatureIndex = getUTFIndex(((CpUtf8) cf.getCp(s.getSignatureIndex())).getText(), cpUTF8, cp);
                                int nameIndex = getUTFIndex("Signature", cpUTF8, cp);
                                attributes.add(new SignatureAttribute(nameIndex, signatureIndex));
                            }
                        }
                        int nameIndex = getUTFIndex(((CpUtf8) cf.getCp(m.getNameIndex())).getText(), cpUTF8, cp);
                        int typeIndex = getUTFIndex(((CpUtf8) cf.getCp(m.getTypeIndex())).getText(), cpUTF8, cp);
                        methods.add(new Method(attributes, m.getAccess(), nameIndex, typeIndex));
                    }

                    List<Attribute> attributes = new ArrayList<>();

                    for (Attribute a : cf.getAttributes()) {
                        if (a instanceof InnerClassesAttribute) {
                            int nameIndex = getUTFIndex(((CpUtf8) cf.getCp(a.getNameIndex())).getText(), cpUTF8, cp);
                            List<InnerClass> innerClasses = new ArrayList<>();
                            for (InnerClass i : ((InnerClassesAttribute) a).getInnerClasses()) {
                                String innerName = ((CpUtf8) cf.getCp(((CpClass) cf.getCp(i.getInnerClassInfoIndex())).getIndex())).getText();
                                int innerClassInfo = getClassIndex(getUTFIndex(innerName, cpUTF8, cp), cpClass, cp);
                                int outerClassInfo;
                                int innerNameIndex;
                                if (i.getOuterClassInfoIndex() == 0) {
                                    outerClassInfo = 0;
                                } else {
                                    String outerName = ((CpUtf8) cf.getCp(((CpClass) cf.getCp(i.getOuterClassInfoIndex())).getIndex())).getText();
                                    outerClassInfo = getClassIndex(getUTFIndex(outerName, cpUTF8, cp), cpClass, cp);
                                }
                                if (i.getInnerNameIndex() == 0) {
                                    innerNameIndex = 0;
                                } else {
                                    innerNameIndex = getUTFIndex(((CpUtf8) cf.getCp(i.getInnerNameIndex())).getText(), cpUTF8, cp);
                                }
                                innerClasses.add(new InnerClass(innerClassInfo, outerClassInfo, innerNameIndex, i.getInnerClassAccessFlags()));
                            }
                            attributes.add(new InnerClassesAttribute(nameIndex, innerClasses));
                        } else if (a instanceof SignatureAttribute) {
                            SignatureAttribute s = (SignatureAttribute) a;
                            int signatureIndex = getUTFIndex(((CpUtf8) cf.getCp(s.getSignatureIndex())).getText(), cpUTF8, cp);
                            int nameIndex = getUTFIndex("Signature", cpUTF8, cp);
                            attributes.add(new SignatureAttribute(nameIndex, signatureIndex));
                        }
                    }

                    ClassFile potemkin = new ClassFile(minor, major, cp, acc, ownClass, superClass, interfaces, fields, methods, attributes);

                    try {
                        zipOut.putNextEntry(new ZipEntry(header.getFileNameAsString()));
                        zipOut.write(cfw.write(potemkin));
                    } catch (InvalidClassException e) {
                        e.printStackTrace();
                    }
                }
            }

            System.out.println("Creating sources jar. This will take quite a while, be patient - it has not crashed!");
            Map<String, Object> ffargs = new HashMap<>();
            ffargs.put(IFernflowerPreferences.INDENT_STRING, "    "); // Default is 3 Spaces, which is nonsense
            ffargs.put(IFernflowerPreferences.DECOMPILE_GENERIC_SIGNATURES, "1"); // Default is false, which is nonsense
            ffargs.put(IFernflowerPreferences.INCLUDE_ENTIRE_CLASSPATH, "1");
            ffargs.put(IFernflowerPreferences.LOG_LEVEL, "ERROR");
            ffargs.put(IFernflowerPreferences.VERIFY_ANONYMOUS_CLASSES, "0");
            ffargs.put(IFernflowerPreferences.BYTECODE_SOURCE_MAPPING, "1");
            ffargs.put(IFernflowerPreferences.DUMP_CODE_LINES, "1");
            ffargs.put(IFernflowerPreferences.DUMP_ORIGINAL_LINES, "1");
            ffargs.put(IFernflowerPreferences.DUMP_ORIGINAL_LINES, "1");
            ffargs.put(IFernflowerPreferences.REMOVE_SYNTHETIC, "0");

            Path sourcesJar = stagingDir.resolve("theotown-" + versionName + "-sources.jar");
            Fernflower ffEngine = new Fernflower(new SingleFileSaver(sourcesJar.toFile()), ffargs, new PrintStreamLogger(System.out));
            ffEngine.addSource(workJar.toFile());
            ffEngine.decompileContext();
            Files.deleteIfExists(workJar);

            Path md5SourcesChecksum = sourcesJar.resolveSibling(sourcesJar.getFileName() + ".md5");
            Path sha1SourcesChecksum = sourcesJar.resolveSibling(sourcesJar.getFileName() + ".sha1");
            Path sha256SourcesChecksum = sourcesJar.resolveSibling(sourcesJar.getFileName() + ".sha256");
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
            try (InputStream var1 = Files.newInputStream(sourcesJar);
                    DigestInputStream var2 = new DigestInputStream(var1, md5Digest);
                    DigestInputStream var3 = new DigestInputStream(var2, sha1Digest);
                    DigestInputStream var4 = new DigestInputStream(var3, sha256Digest)) {
                var4.readAllBytes();
            }
            Files.writeString(md5SourcesChecksum, toHexHash(md5Digest.digest()), StandardOpenOption.CREATE);
            Files.writeString(sha1SourcesChecksum, toHexHash(sha1Digest.digest()), StandardOpenOption.CREATE);
            Files.writeString(sha256SourcesChecksum, toHexHash(sha256Digest.digest()), StandardOpenOption.CREATE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        try {
            Path md5SourcesChecksum = potemkinJar.resolveSibling(potemkinJar.getFileName() + ".md5");
            Path sha1SourcesChecksum = potemkinJar.resolveSibling(potemkinJar.getFileName() + ".sha1");
            Path sha256SourcesChecksum = potemkinJar.resolveSibling(potemkinJar.getFileName() + ".sha256");
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
            try (InputStream var1 = Files.newInputStream(potemkinJar);
                    DigestInputStream var2 = new DigestInputStream(var1, md5Digest);
                    DigestInputStream var3 = new DigestInputStream(var2, sha1Digest);
                    DigestInputStream var4 = new DigestInputStream(var3, sha256Digest)) {
                var4.readAllBytes();
            }
            Files.writeString(md5SourcesChecksum, toHexHash(md5Digest.digest()), StandardOpenOption.CREATE);
            Files.writeString(sha1SourcesChecksum, toHexHash(sha1Digest.digest()), StandardOpenOption.CREATE);
            Files.writeString(sha256SourcesChecksum, toHexHash(sha256Digest.digest()), StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String toHexHash(byte[] hash) {
        final StringBuilder hex = new StringBuilder(2 * hash.length);
        for (final byte b : hash) {
            int x = ((int) b) & 0x00FF;
            if (x < 16) {
                hex.append('0');
            }
            hex.append(Integer.toHexString(x));
        }
        return hex.toString();
    }

    private static int transfer(CpClass origin, ClassFile cf, Map<String, Integer> cpUTF8, Map<Integer, Integer> cpClass, ConstPool cp) {
        CpUtf8 name = (CpUtf8) cf.getCp(origin.getIndex());
        return getClassIndex(getUTFIndex(name.getText(), cpUTF8, cp), cpClass, cp);
    }

    private static int getClassIndex(int utfIndex, Map<Integer, Integer> cpClass, ConstPool cp) {
        Integer i = cpClass.get(utfIndex);
        if (i != null) {
            return i.intValue();
        }
        CpClass e = new CpClass(utfIndex);
        int index = cp.size() + 1;
        cp.add(index, e);
        cpClass.put(utfIndex, index);
        return index;
    }

    private static int getUTFIndex(String utf, Map<String, Integer> cpUTF8, ConstPool cp) {
        Integer i = cpUTF8.get(utf);
        if (i != null) {
            return i.intValue();
        }
        CpUtf8 e = new CpUtf8(utf);
        int index = cp.size() + 1;
        cp.add(index, e);
        cpUTF8.put(utf, index);
        return index;
    }
}
