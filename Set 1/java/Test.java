package java;

import java.util.ArrayList;
import java.util.List;

public class Test
{
    def getSubmatrix(matrix, i, j):
        submatrix = [item for x, item in enumerate(matrix) if x != i]
        for x, elem in enumerate(submatrix):
            submatrix[x] = elem[:j] + elem[j+1:]

        return submatrix

    public static int getSubmatrix(int[][] matrix, int i, int j)
    {
        List<List<Integer>> subMatrix = new ArrayList<List<Integer>>();
        for (int x = 0; x < matrix.length; x++)
        {
            if (x != i)
            {
                subMatrix.add(matrix[x]);
            }
        }
    }


    public static int solution(int[][] m)
    {
        int[][] matrix = {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}};
        return 0;
    }

    
}
