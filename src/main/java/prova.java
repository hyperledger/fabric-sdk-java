import java.util.Arrays;

/**
 * Created by rineholt on 11/19/16.
 */
public class prova {

    public static void main( String[] args){
        StringBuffer sb = new StringBuffer(200);
        String sep ="";
        for(String arg : args){
            sb.append(sep).append(arg);
            sep = ", ";

        }
        System.out.println("Program args:" + sb);
        System.err.println("Program args:" + sb);

        String foo[]={"a","b"};
        foo = Arrays.copyOfRange(foo, 1, foo.length);

        System.err.println("Program args:" + foo);
    }
}
